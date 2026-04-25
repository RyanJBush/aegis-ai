import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { api, setAuthToken } from '../api'

function LoginPage({ onLogin }) {
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', password: '' })
  const [error, setError] = useState('')

  const handleSubmit = async (event) => {
    event.preventDefault()
    setError('')
    try {
      const { data } = await api.post('/api/auth/login', form)
      onLogin(data.access_token)
      setAuthToken(data.access_token)
      navigate('/dashboard')
    } catch {
      setError('Invalid credentials')
    }
  }

  return (
    <section className="mx-auto mt-16 max-w-md rounded border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-4 text-2xl font-semibold">Login</h2>
      <form className="space-y-3" onSubmit={handleSubmit}>
        <input
          className="w-full rounded bg-slate-800 p-2"
          placeholder="Username"
          value={form.username}
          onChange={(event) =>
            setForm((prev) => ({ ...prev, username: event.target.value }))
          }
          required
        />
        <input
          type="password"
          className="w-full rounded bg-slate-800 p-2"
          placeholder="Password"
          value={form.password}
          onChange={(event) =>
            setForm((prev) => ({ ...prev, password: event.target.value }))
          }
          required
        />
        {error ? <p className="text-sm text-rose-400">{error}</p> : null}
        <button
          className="w-full rounded bg-blue-600 p-2 font-medium"
          type="submit"
        >
          Sign in
        </button>
      </form>
      <p className="mt-4 text-xs text-slate-400">
        Create a user through /api/auth/register.
      </p>
    </section>
  )
}

export default LoginPage
