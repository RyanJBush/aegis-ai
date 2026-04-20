import { Navigate, Route, Routes } from 'react-router-dom';

import MainLayout from './layouts/MainLayout';
import AppInterfacePage from './pages/AppInterfacePage';
import DashboardPage from './pages/DashboardPage';
import LoginPage from './pages/LoginPage';
import ScanResultsPage from './pages/ScanResultsPage';
import VulnerabilityDetailPage from './pages/VulnerabilityDetailPage';

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={<MainLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="app-interface" element={<AppInterfacePage />} />
        <Route path="scan-results" element={<ScanResultsPage />} />
        <Route path="vulnerabilities/:id" element={<VulnerabilityDetailPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
