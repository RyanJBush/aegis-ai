import PageHeader from '../components/PageHeader';

function AppInterfacePage() {
  return (
    <section className="stack">
      <PageHeader
        title="App Interface"
        subtitle="Simulate suspicious request payloads against monitored endpoints."
      />
      <section className="card form-card">
        <label htmlFor="target">Target URL</label>
        <input id="target" type="url" placeholder="https://app.example.com/login" />

        <label htmlFor="payload">Payload</label>
        <textarea
          id="payload"
          rows={8}
          placeholder={`' OR 1=1 --\n<script>alert(1)</script>`}
        ></textarea>

        <button type="button">Run Security Scan</button>
        <small>UI-only workflow placeholder. Wire this to /api/v1/scanning/run next.</small>
      </section>
    </section>
  );
}

export default AppInterfacePage;
