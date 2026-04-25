import { ReactElement } from 'react';
import { Navigate } from 'react-router-dom';

import { hasAuthToken } from '../services/api';

type ProtectedRouteProps = {
  children: ReactElement;
};

function ProtectedRoute({ children }: ProtectedRouteProps) {
  if (!hasAuthToken()) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

export default ProtectedRoute;
