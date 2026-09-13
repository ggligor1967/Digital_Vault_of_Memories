// @ts-check
/**
 * Flat ESLint configuration for the whole workspace.
 *
 * One configuration rather than one per package: the rules that matter here
 * are architectural (what the renderer may import, what may be thrown across
 * the IPC boundary) and those are properties of the repository, not of a
 * package.
 */
import js from '@eslint/js';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/target/**',
      'apps/desktop/src-tauri/gen/**',
      '**/coverage/**',
      '.dvm-local/**',
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,

  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // The IPC boundary carries `AppError` envelopes (Blueprint v2 §23.1),
      // not JavaScript errors: an `Error` would carry a stack across the
      // boundary, which is exactly what the envelope exists to prevent. Both
      // rules below assume `Error` is always the right rejection value, so
      // they are wrong for this codebase specifically.
      '@typescript-eslint/only-throw-error': 'off',
      '@typescript-eslint/prefer-promise-reject-errors': 'off',
      '@typescript-eslint/prefer-nullish-coalescing': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      'no-console': ['error', { allow: ['warn', 'error'] }],
      eqeqeq: ['error', 'always'],
    },
  },

  // Renderer: React rules plus the import restrictions that keep the trust
  // boundary intact.
  {
    files: ['apps/desktop/src/**/*.{ts,tsx}'],
    languageOptions: {
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@tauri-apps/api',
              message:
                'Import Tauri only from apps/desktop/src/ipc/tauri-adapter.ts. Components depend on FoundationPort.',
            },
          ],
          patterns: [
            {
              group: ['node:*'],
              message: 'The renderer has no host access (INV-013).',
            },
            {
              group: ['@tauri-apps/plugin-*'],
              message:
                'Tauri plugins that grant host authority are forbidden (INV-012, INV-013). Use a typed command.',
            },
          ],
        },
      ],
    },
  },

  // The adapter is the one place allowed to reach for Tauri.
  {
    files: ['apps/desktop/src/ipc/tauri-adapter.ts'],
    rules: {
      'no-restricted-imports': 'off',
    },
  },

  // Vite's config lives outside the renderer's tsconfig on purpose (it is Node
  // code, and giving the renderer Node types would weaken the trust boundary),
  // so the type-aware rules are pointed at the Node project explicitly.
  {
    files: ['apps/desktop/vite.config.ts'],
    languageOptions: {
      parserOptions: {
        projectService: false,
        project: ['./apps/desktop/tsconfig.node.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },

  // Node-side configuration, scripts and repository tests.
  {
    files: [
      '*.config.{js,ts}',
      'scripts/**/*.mjs',
      'tests/security/**/*.ts',
      'apps/desktop/vite.config.ts',
      'apps/desktop/vitest.setup.ts',
      'eslint.config.js',
    ],
    languageOptions: {
      globals: globals.nodeBuiltin,
    },
    rules: {
      // Scripts report progress on stdout by design; that is their output.
      'no-console': 'off',
    },
  },

  // Verification scripts are plain JavaScript, so type-aware rules do not
  // apply to them.
  {
    files: ['scripts/**/*.mjs', 'eslint.config.js'],
    extends: [tseslint.configs.disableTypeChecked],
  },

  // Tests may assert on deliberately malformed values.
  {
    files: ['**/*.test.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },

  // The generated contract is produced by the Rust generator and must not be
  // reshaped by lint rules.
  {
    files: ['packages/contracts/src/generated/**/*.ts'],
    rules: {
      '@typescript-eslint/consistent-type-definitions': 'off',
    },
  },
);
