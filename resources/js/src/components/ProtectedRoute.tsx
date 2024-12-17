import { Children } from 'react';
import { Navigate} from 'react-router-dom';

interface ProtectedRouteProps {
    allowedRoles: string[];
    children: JSX.Element;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ allowedRoles, children }) => {
    // const userRole = localStorage.getItem('user_role'); // Retrieved from response
    
    // // Redirect if no role or role mismatch
    // if (!userRole || !allowedRoles.includes(userRole)) {
    //     return <Navigate to="/auth/boxed-signin" />;
    // }

    const userRoles = JSON.parse(sessionStorage.getItem('user_roles') || '[]'); // Get roles from sessionStorage

    // Check if at least one role matches the allowed roles
    const hasAccess = userRoles.some((role: string) => allowedRoles.includes(role));

    // Redirect if no access
    if (!hasAccess) {
        return <Navigate to="/auth/boxed-signin" replace />;
    }

    console.log('Stored User Roles:', userRoles);
    console.log('Allowed Roles:', allowedRoles);
    console.log('Access Granted:', hasAccess);

    return children;
};

export default ProtectedRoute;