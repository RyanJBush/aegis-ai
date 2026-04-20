import { Link, Outlet, useNavigate } from 'react-router-dom'

function Layout({ token, onLogout }) {
  const navigate = useNavigate()

  const handleLogout = () => {
    onLogout()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800">
        <div className="mx-auto flex max-w-6xl items-center justify-between p-4">
          <h1 className="text-xl font-semibold">Aegis AI</h1>
          {token ? (
            <nav className="flex items-center gap-4 text-sm">
              <Link to="/dashboard">Dashboard</Link>
              <Link to="/app">App Interface</Link>
              <Link to="/scan-results">Scan Results</Link>
              <button
                className="rounded bg-slate-700 px-3 py-1"
                onClick={handleLogout}
              >
                Logout
              </button>
            </nav>
          ) : null}
        </div>
      </header>
      <main className="mx-auto max-w-6xl p-4">
        <Outlet />
      </main>
    </div>
  )
}

export default Layout
