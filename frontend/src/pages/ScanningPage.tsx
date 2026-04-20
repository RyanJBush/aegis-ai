import PageHeader from '../components/PageHeader';

function ScanningPage() {
  return (
    <section className="card">
      <PageHeader title="Scanning" subtitle="Configure and launch vulnerability scans." />
      <button type="button">Start New Scan</button>
      <p>Scan workflow placeholder.</p>
    </section>
  );
}

export default ScanningPage;
