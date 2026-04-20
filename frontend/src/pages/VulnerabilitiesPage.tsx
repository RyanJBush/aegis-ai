import PageHeader from '../components/PageHeader';

function VulnerabilitiesPage() {
  return (
    <section className="card">
      <PageHeader title="Vulnerabilities" subtitle="Track and prioritize discovered issues." />
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>VULN-001</td>
            <td>High</td>
            <td>Open</td>
          </tr>
        </tbody>
      </table>
    </section>
  );
}

export default VulnerabilitiesPage;
