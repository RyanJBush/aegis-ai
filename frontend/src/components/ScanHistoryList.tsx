import { ScanJob } from '../types';

type ScanHistoryListProps = {
  scans: ScanJob[];
};

function ScanHistoryList({ scans }: ScanHistoryListProps) {
  return (
    <ul className="scan-history">
      {scans.map((scan) => (
        <li key={scan.id} className="scan-item">
          <div>
            <strong>{scan.id}</strong>
            <p>{scan.target}</p>
          </div>
          <div>
            <span className={`status-pill status-${scan.status}`}>{scan.status.toUpperCase()}</span>
            <p>
              {scan.findings} findings • {scan.duration}
            </p>
          </div>
        </li>
      ))}
    </ul>
  );
}

export default ScanHistoryList;
