import { Children } from 'react';
import { Navigate} from 'react-router-dom';

interface ProtectedRouteProps {
    allowedRoles: string[];
    children: JSX.Element;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ allowedRoles, children }) => {
    const userRole = localStorage.getItem('user_role'); // Retrieved from response

    // Redirect if no role or role mismatch
    if (!userRole || !allowedRoles.includes(userRole)) {
        return <Navigate to="/auth/boxed-signin" />;
    }

    return children;
};

export default ProtectedRoute;