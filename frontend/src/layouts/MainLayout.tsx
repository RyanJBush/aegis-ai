import { Link, Outlet, useLocation } from 'react-router-dom';

const navItems = [
  { path: '/', label: 'Dashboard' },
  { path: '/app-interface', label: 'App Interface' },
  { path: '/scan-results', label: 'Scan Results' },
];

function MainLayout() {
  const location = useLocation();

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
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}

export default MainLayout;
