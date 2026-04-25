function LoginPage() {
  return (
    <section className="card centered form-card">
      <h2>Security Analyst Login</h2>
      <p>Access Aegis AI monitoring, triage, and incident response workflows.</p>
      <label htmlFor="email">Email</label>
      <input id="email" type="email" placeholder="analyst@company.com" />
      <label htmlFor="password">Password</label>
      <input id="password" type="password" placeholder="••••••••••••" />
      <button type="button">Sign In</button>
    </section>
  );
}

export default LoginPage;
