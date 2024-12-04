// import { PropsWithChildren, useEffect, useState } from 'react';
// import { useDispatch, useSelector } from 'react-redux';
// // import { useKeycloak } from '@react-keycloak/web';
// import axios from 'axios';
// import { IRootState } from './store';
// import { toggleRTL, toggleTheme, toggleLocale, toggleMenu, toggleLayout, toggleAnimation, toggleNavbar, toggleSemidark } from './store/themeConfigSlice';
// import store from './store';

// function App({ children }: PropsWithChildren) {
//     const themeConfig = useSelector((state: IRootState) => state.themeConfig);
//     const dispatch = useDispatch();
//     // const { keycloak } = useKeycloak();
//     const [authenticated, setAuthenticated] = useState<boolean | null>(null);

//     useEffect(() => {
//         dispatch(toggleTheme(localStorage.getItem('theme') || themeConfig.theme));
//         dispatch(toggleMenu(localStorage.getItem('menu') || themeConfig.menu));
//         dispatch(toggleLayout(localStorage.getItem('layout') || themeConfig.layout));
//         dispatch(toggleRTL(localStorage.getItem('rtlClass') || themeConfig.rtlClass));
//         dispatch(toggleAnimation(localStorage.getItem('animation') || themeConfig.animation));
//         dispatch(toggleNavbar(localStorage.getItem('navbar') || themeConfig.navbar));
//         dispatch(toggleLocale(localStorage.getItem('i18nextLng') || themeConfig.locale));
//         dispatch(toggleSemidark(localStorage.getItem('semidark') || themeConfig.semidark));
//     }, [dispatch, themeConfig.theme, themeConfig.menu, themeConfig.layout, themeConfig.rtlClass, themeConfig.animation, themeConfig.navbar, themeConfig.locale, themeConfig.semidark]);

// //     return keycloak.authenticated ? (
// //         <div
// //             className={`${(store.getState().themeConfig.sidebar && 'toggle-sidebar') || ''} ${themeConfig.menu} ${themeConfig.layout} ${
// //                 themeConfig.rtlClass
// //             } main-section antialiased relative font-nunito text-sm font-normal`}
// //         >
// //             {children}
// //         </div>

// //     ) : (
// //         <div>Loading...</div>
// //     );
// // }

// if (!authenticated) {
//     return <div>Loading...</div>;
// }

// return (
//     <div
//         className={`${(store.getState().themeConfig.sidebar && 'toggle-sidebar') || ''} ${themeConfig.menu} ${themeConfig.layout} ${
//             themeConfig.rtlClass
//         } main-section antialiased relative font-nunito text-sm font-normal`}
//     >
//         {children}
//     </div>
// );
// }

// export default App;

import { PropsWithChildren, useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import axios from 'axios';
import { IRootState } from './store';
import { toggleRTL, toggleTheme, toggleLocale, toggleMenu, toggleLayout, toggleAnimation, toggleNavbar, toggleSemidark } from './store/themeConfigSlice';
import store from './store';
import { useNavigate } from 'react-router-dom';

function App({ children }: PropsWithChildren) {
    const themeConfig = useSelector((state: IRootState) => state.themeConfig);
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);

    useEffect(() => {
        // Initialize theme configuration
        dispatch(toggleTheme(localStorage.getItem('theme') || themeConfig.theme));
        dispatch(toggleMenu(localStorage.getItem('menu') || themeConfig.menu));
        dispatch(toggleLayout(localStorage.getItem('layout') || themeConfig.layout));
        dispatch(toggleRTL(localStorage.getItem('rtlClass') || themeConfig.rtlClass));
        dispatch(toggleAnimation(localStorage.getItem('animation') || themeConfig.animation));
        dispatch(toggleNavbar(localStorage.getItem('navbar') || themeConfig.navbar));
        dispatch(toggleLocale(localStorage.getItem('i18nextLng') || themeConfig.locale));
        dispatch(toggleSemidark(localStorage.getItem('semidark') || themeConfig.semidark));

        // Check authentication status
        const checkAuth = async () => {
            try {
                const response = await axios.get<{ authenticated: boolean }>(
                    `${import.meta.env.VITE_API_BASE_URL}/auth/check`,
                    { withCredentials: true }
                );
                setIsAuthenticated(response.data.authenticated);
            } catch (error) {
                console.error('Error checking authentication:', error);
                setIsAuthenticated(false);
                navigate('/auth/boxed-signin');
            }
        };

        checkAuth();
    }, [dispatch, themeConfig, navigate]);

    if (isAuthenticated === null) {
        // Show a loading indicator while authentication status is being checked
        return <div>Loading...</div>;
    }

    return isAuthenticated ? (
        <div
            className={`${(store.getState().themeConfig.sidebar && 'toggle-sidebar') || ''} ${themeConfig.menu} ${themeConfig.layout} ${
                themeConfig.rtlClass
            } main-section antialiased relative font-nunito text-sm font-normal`}
        >
            {children}
        </div>
    ) : (
        <div>Redirecting to login...</div>
    );
}

export default App;
