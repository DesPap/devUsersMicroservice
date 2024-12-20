import { createBrowserRouter } from 'react-router-dom';
import BlankLayout from '../components/Layouts/BlankLayout';
import DefaultLayout from '../components/Layouts/DefaultLayout';
import ProtectedRoute from '../components/ProtectedRoute';
import { routes } from './routes';

// const finalRoutes = routes.map((route) => {
//     return {
//         ...route,
//         element: route.layout === 'blank' ? <BlankLayout>{route.element}</BlankLayout> : <DefaultLayout>{route.element}</DefaultLayout>,
//     };
// });


// Add ProtectedRoute for userRoutes
const finalRoutes = routes.map((route) => {
    return {
        ...route,
        element: route.layout === 'blank'
            ? <BlankLayout>{route.element}</BlankLayout>
            : (
                <ProtectedRoute allowedRoles={['user', 'admin']}>
                    <DefaultLayout>{route.element}</DefaultLayout>
                </ProtectedRoute>
            ),
    };
});

const router = createBrowserRouter(finalRoutes);

export default router;


