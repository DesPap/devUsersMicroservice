import { createBrowserRouter } from 'react-router-dom';
import BlankLayout from '../components/Layouts/BlankLayout';
import DefaultLayout from '../components/Layouts/DefaultLayout';
import { routes } from './routes';

const finalRoutes = routes.map((route) => {
    return {
        ...route,
        element: route.layout === 'blank' ? <BlankLayout>{route.element}</BlankLayout> : <DefaultLayout>{route.element}</DefaultLayout>,
    };
});

const router = createBrowserRouter(finalRoutes);

export default router;

// import React from 'react';
// import ReactDOM from 'react-dom/client';
// import { RouterProvider, createBrowserRouter } from 'react-router-dom';
// import { routes } from './routes'; // Import simplified routes

// // Create the router directly from the routes
// const router = createBrowserRouter(routes);

// ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
//     <React.StrictMode>
//         <RouterProvider router={router} />
//     </React.StrictMode>
// );




// import React from 'react';
// import ReactDOM from 'react-dom/client';

// const App = () => <div>Hello, World!</div>;

// ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
//     <React.StrictMode>
//         <App />
//     </React.StrictMode>
// );