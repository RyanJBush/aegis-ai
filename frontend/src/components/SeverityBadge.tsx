import { Severity } from '../types';

type SeverityBadgeProps = {
  severity: Severity;
};

function SeverityBadge({ severity }: SeverityBadgeProps) {
  return <span className={`severity-badge severity-${severity}`}>{severity.toUpperCase()}</span>;
}

export default SeverityBadge;
