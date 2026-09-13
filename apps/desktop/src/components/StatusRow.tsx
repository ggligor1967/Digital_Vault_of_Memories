/**
 * A labelled read-only value in the foundation panel.
 *
 * Rendered as a description list row so screen readers announce the label with
 * its value (Blueprint v2 §28.1 requires an accessible baseline from the
 * start, not as a later pass).
 */
export interface StatusRowProps {
  /** Human-readable label. */
  label: string;
  /** The value to display. */
  value: string;
  /** Optional test hook for the value element. */
  valueTestId?: string;
}

/** Renders one label/value pair. */
export function StatusRow({ label, value, valueTestId }: StatusRowProps) {
  return (
    <div className="status-row">
      <dt className="status-row__label">{label}</dt>
      <dd className="status-row__value" data-testid={valueTestId}>
        {value}
      </dd>
    </div>
  );
}
