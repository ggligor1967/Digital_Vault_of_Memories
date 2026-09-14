//! Single ownership and admission boundary for one local vault.
use dvm_domain::{
    AppError, ErrorCode,
    security::{SessionBackend, VaultState},
    storage::ReconciliationHealth,
};
use std::sync::{Mutex, MutexGuard};

struct Inner<B: SessionBackend> {
    state: VaultState,
    backend: Option<B>,
    active: Option<B::Active>,
}

/// Serializes transitions and operations. Live handles never leave a borrowed scope.
pub struct VaultSession<B: SessionBackend> {
    inner: Mutex<Inner<B>>,
}
impl<B: SessionBackend> Default for VaultSession<B> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                state: VaultState::Closed,
                backend: None,
                active: None,
            }),
        }
    }
}
impl<B: SessionBackend> VaultSession<B> {
    fn guard(&self) -> Result<MutexGuard<'_, Inner<B>>, AppError> {
        match self.inner.lock() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                let mut inner = poisoned.into_inner();
                inner.active = None;
                inner.state = VaultState::Locked;
                Err(AppError::new(ErrorCode::VaultLocked))
            }
        }
    }
    /// Selects an already validated trusted backend; no credential is installed.
    /// # Errors
    /// A vault is already selected or synchronization failed.
    pub fn attach(&self, backend: B) -> Result<(), AppError> {
        let mut inner = self.guard()?;
        if inner.state != VaultState::Closed {
            return Err(AppError::new(ErrorCode::VaultLocked));
        }
        inner.backend = Some(backend);
        inner.state = VaultState::Locked;
        Ok(())
    }
    /// Non-private operational status.
    /// # Errors
    /// Poisoned synchronization fails closed.
    pub fn state(&self) -> Result<VaultState, AppError> {
        Ok(self.guard()?.state)
    }
    /// Only one unlock transition can execute at a time.
    /// # Errors
    /// Authentication or storage failure returns to LOCKED without live secrets.
    pub fn unlock(&self, credential: &B::Credential) -> Result<(), AppError> {
        let mut inner = self.guard()?;
        if inner.state != VaultState::Locked {
            return Err(AppError::new(ErrorCode::VaultLocked));
        }
        inner.state = VaultState::Unlocking;
        let result = inner
            .backend
            .as_ref()
            .ok_or_else(|| AppError::new(ErrorCode::VaultLocked))?
            .unlock(credential);
        match result {
            Ok(active) => {
                inner.state = if B::health(&active) == ReconciliationHealth::Healthy {
                    VaultState::Open
                } else {
                    VaultState::DegradedReadOnly
                };
                inner.active = Some(active);
                Ok(())
            }
            Err(error) => {
                inner.active = None;
                inner.state = VaultState::Locked;
                Err(error)
            }
        }
    }
    /// Orders admission against lock and retains ownership for the whole operation.
    /// # Errors
    /// Every non-OPEN state returns `VaultLocked` before executing the operation.
    pub fn with_open<T>(
        &self,
        operation: impl FnOnce(&B::Active) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        let mut inner = self.guard()?;
        if inner.state != VaultState::Open {
            return Err(AppError::new(ErrorCode::VaultLocked));
        }
        let active = inner
            .active
            .as_ref()
            .ok_or_else(|| AppError::new(ErrorCode::VaultLocked))?;
        if B::health(active) != ReconciliationHealth::Healthy {
            inner.state = VaultState::DegradedReadOnly;
            return Err(AppError::new(ErrorCode::VaultLocked));
        }
        let result = operation(active);
        if B::health(active) != ReconciliationHealth::Healthy {
            inner.state = VaultState::DegradedReadOnly;
        }
        result
    }
    /// Closes admission, drops storage and keys, then reports LOCKED.
    /// # Errors
    /// No selected vault or poisoned synchronization.
    pub fn lock(&self) -> Result<(), AppError> {
        let mut inner = self.guard()?;
        if inner.state == VaultState::Closed {
            return Err(AppError::new(ErrorCode::VaultLocked));
        }
        inner.state = VaultState::Locking;
        inner.active = None;
        inner.state = VaultState::Locked;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    struct Backend {
        attempts: Arc<AtomicUsize>,
        live: Arc<AtomicUsize>,
        degraded: Arc<AtomicBool>,
    }
    struct Active {
        live: Arc<AtomicUsize>,
        degraded: Arc<AtomicBool>,
    }
    impl Drop for Active {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl SessionBackend for Backend {
        type Credential = bool;
        type Active = Active;
        fn unlock(&self, valid: &bool) -> Result<Active, AppError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if !valid {
                return Err(AppError::new(ErrorCode::BadPassphrase));
            }
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Active {
                live: self.live.clone(),
                degraded: self.degraded.clone(),
            })
        }
        fn health(active: &Active) -> ReconciliationHealth {
            if active.degraded.load(Ordering::SeqCst) {
                ReconciliationHealth::DegradedReadOnly
            } else {
                ReconciliationHealth::Healthy
            }
        }
    }
    #[test]
    fn locked_operation_guard_is_effective() -> TestResult {
        let session = VaultSession::default();
        session.attach(Backend {
            attempts: Arc::new(AtomicUsize::new(0)),
            live: Arc::new(AtomicUsize::new(0)),
            degraded: Arc::new(AtomicBool::new(false)),
        })?;
        session.unlock(&true)?;
        session.lock()?;
        let result = session.with_open(|_| Ok(()));
        assert!(result.is_err(), "locked operation was admitted");
        assert_eq!(
            result.err().ok_or("locked error")?.code,
            ErrorCode::VaultLocked
        );
        Ok(())
    }
    #[test]
    fn concurrent_unlock_lock_ordering_and_key_owner_release() -> TestResult {
        let live = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        let degraded = Arc::new(AtomicBool::new(false));
        let session = Arc::new(VaultSession::default());
        session.attach(Backend {
            attempts: attempts.clone(),
            live: live.clone(),
            degraded: degraded.clone(),
        })?;
        assert!(session.unlock(&false).is_err());
        assert_eq!(live.load(Ordering::SeqCst), 0);
        let start = Arc::new(Barrier::new(3));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let session = session.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    session.unlock(&true)
                })
            })
            .collect();
        start.wait();
        let mut success = 0;
        for thread in threads {
            if thread.join().map_err(|_| "thread panicked")?.is_ok() {
                success += 1;
            }
        }
        assert_eq!(success, 1);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(live.load(Ordering::SeqCst), 1);
        let entered = Arc::new(Barrier::new(2));
        let finish = Arc::new(Barrier::new(2));
        let operation = {
            let s = session.clone();
            let entered = entered.clone();
            let finish = finish.clone();
            std::thread::spawn(move || {
                s.with_open(|_| {
                    entered.wait();
                    finish.wait();
                    Ok(())
                })
            })
        };
        entered.wait();
        let locking = Arc::new(Barrier::new(2));
        let lock = {
            let s = session.clone();
            let locking = locking.clone();
            std::thread::spawn(move || {
                locking.wait();
                s.lock()
            })
        };
        locking.wait();
        assert_eq!(live.load(Ordering::SeqCst), 1);
        finish.wait();
        operation.join().map_err(|_| "operation panicked")??;
        lock.join().map_err(|_| "lock panicked")??;
        assert_eq!(session.state()?, VaultState::Locked);
        assert_eq!(live.load(Ordering::SeqCst), 0);
        let called = AtomicBool::new(false);
        assert_eq!(
            session
                .with_open(|_| {
                    called.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .err()
                .ok_or("locked")?
                .code,
            ErrorCode::VaultLocked
        );
        assert!(!called.load(Ordering::SeqCst));
        session.unlock(&true)?;
        degraded.store(true, Ordering::SeqCst);
        assert!(session.with_open(|_| Ok(())).is_err());
        assert_eq!(session.state()?, VaultState::DegradedReadOnly);
        session.lock()?;
        assert_eq!(live.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
