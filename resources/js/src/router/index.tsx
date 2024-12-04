import { createBrowserRouter, Navigate } from 'react-router-dom';
import axios from 'axios';
import { useEffect, useState } from 'react';
import BlankLayout from '../components/Layouts/BlankLayout';
import DefaultLayout from '../components/Layouts/DefaultLayout';
import { routes } from './routes';
// import { useKeycloak } from '@react-keycloak/web';

// const finalRoutes = routes.map((route) => {
//     return {
//         ...route,
//         element: route.layout === 'blank' ? <BlankLayout>{route.element}</BlankLayout> : <DefaultLayout>{route.element}</DefaultLayout>,
//     };
// });

// const router = createBrowserRouter(finalRoutes);

// export default router;

// Check authentication function
interface AuthCheckResponse {
    authenticated: boolean;
}

// Function to check authentication status
const checkAuthentication = async (): Promise<boolean> => {
    try {
        const response = await axios.get<AuthCheckResponse>(
            `${import.meta.env.VITE_API_BASE_URL}/auth/check`,
            { withCredentials: true }
        );
        return response.data.authenticated;
    } catch (error) {
        console.error('Error checking authentication:', error);
        return false;
    }
};

// AuthGuard component for protected routes
const AuthGuard = ({ children }: { children: JSX.Element }) => {
    const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);

    useEffect(() => {
        const fetchAuthStatus = async () => {
            const authenticated = await checkAuthentication();
            setIsAuthenticated(authenticated);
        };

        fetchAuthStatus();
    }, []);

    if (isAuthenticated === null) {
        return <div>Loading...</div>;
    }

    return isAuthenticated ? children : <Navigate to="/auth/boxed-signin" />;
};

// // Map routes with layouts and AuthGuard
// const finalRoutes = routes.map((route) => {
//     const element = route.protected ? (
//         <AuthGuard>{route.element}</AuthGuard>
//     ) : (
//         route.element
//     );

//     return {
//         ...route,
//         element: route.layout === 'blank' ? (
//             <BlankLayout>{element}</BlankLayout>
//         ) : (
//             <DefaultLayout>{element}</DefaultLayout>
//         ),
//     };
// });

const finalRoutes = routes.map((route) => {
    const element = route.layout === 'blank' ? (
        <BlankLayout>{route.element}</BlankLayout>
    ) : (
        <DefaultLayout>{route.element}</DefaultLayout>
    );

    return {
        ...route,
        element,
    };
});

const router = createBrowserRouter(finalRoutes);

export default router;
