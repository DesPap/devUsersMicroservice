import React, { Suspense } from 'react';
import ReactDOM from 'react-dom/client';
import AllPages from './pages/Pages/AllPages';

// Perfect Scrollbar
import 'react-perfect-scrollbar/dist/css/styles.css';

// Tailwind css
import './tailwind.css';

// i18n (needs to be bundled)
import './i18n';

// Router
import { RouterProvider } from 'react-router-dom';
import router from './router/index';

// Redux
import { Provider } from 'react-redux';
import store from './store/index';

// import keycloak from './keycloak';
// import { ReactKeycloakProvider } from '@react-keycloak/web';

const eventLogger = (eventType: string) => {
    console.log(`[Keycloak Event] ${eventType}`);
};

const tokenLogger = (tokens: any) => {
    console.log(`[Keycloak Token]`, tokens);
};

// ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
//     <React.StrictMode>
//         {/* <ReactKeycloakProvider authClient={keycloak} onEvent={eventLogger} onTokens={tokenLogger}> */}
//             <Suspense>
//                 <Provider store={store}>
//                     <RouterProvider router={router} />
//                 </Provider>
//             </Suspense>
//         {/* </ReactKeycloakProvider> */}
//     </React.StrictMode>
// );
console.log("React App Mounted");
ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
    <React.StrictMode>
        <AllPages />
    </React.StrictMode>
);

