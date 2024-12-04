import React from 'react';
import { routes } from '../../router/routes'; // Adjust the import path to your routes file
import { Link } from 'react-router-dom';

const AllPages = () => {
    return (
        <div style={{ padding: '20px' }}>
            <h1>All Pages in the App</h1>
            <ul>
                {routes.map((route, index) => (
                    <li key={index} style={{ marginBottom: '10px' }}>
                        <Link to={route.path} style={{ textDecoration: 'none', color: 'blue' }}>
                            {route.path} - {route.element.type?.name || 'Unnamed Component'}
                        </Link>
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default AllPages;