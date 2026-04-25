import { FormEvent, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { hasAuthToken, postJson, setAuthToken } from '../services/api';

type LoginResponse = {
  access_token: string;
};

function LoginPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('analyst@example.com');
  const [password, setPassword] = useState('StrongPassw0rd!');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (hasAuthToken()) {
      navigate('/', { replace: true });
    }
  }, [navigate]);

  async function handleLogin(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await postJson<LoginResponse, { email: string; password: string }>(
        '/auth/login',
        { email, password },
      );
      setAuthToken(response.access_token);
      navigate('/', { replace: true });
    } catch {
      setError('Login failed. Register the user first via API or use valid credentials.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="card centered form-card" onSubmit={handleLogin}>
      <h2>Security Analyst Login</h2>
      <p>Access Aegis AI monitoring, triage, and incident response workflows.</p>
      {error && <p className="notice error">{error}</p>}
      <label htmlFor="email">Email</label>
      <input
        id="email"
        type="email"
        placeholder="analyst@company.com"
        value={email}
        onChange={(event) => setEmail(event.target.value)}
      />
      <label htmlFor="password">Password</label>
      <input
        id="password"
        type="password"
        placeholder="••••••••••••"
        value={password}
        onChange={(event) => setPassword(event.target.value)}
      />
      <button type="submit" disabled={loading}>{loading ? 'Signing In…' : 'Sign In'}</button>
    </form>
  );
}

export default LoginPage;
