import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';

import { clearAuthToken } from '../services/api';

const navItems = [
  { path: '/', label: 'Dashboard' },
  { path: '/scan-results', label: 'Scan Results' },
  { path: '/scanning', label: 'Scan Ops' },
  { path: '/remediation', label: 'Remediation Queue' },
  { path: '/app-interface', label: 'App Interface' },
];

function MainLayout() {
  const location = useLocation();
  const navigate = useNavigate();

  function handleLogout() {
    clearAuthToken();
    navigate('/login', { replace: true });
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <h1>Aegis AI</h1>
        <p className="sidebar-subtitle">Application Security Command Center</p>
        <nav>
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-link ${location.pathname === item.path ? 'active' : ''}`}
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <button className="logout-button" type="button" onClick={handleLogout}>
          Log out
        </button>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}

export default MainLayout;
