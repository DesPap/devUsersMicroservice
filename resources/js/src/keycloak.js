import Keycloak from 'keycloak-js';

// Initialize Keycloak with configuration fetched from Laravel's backend
const keycloak = new Keycloak({
    url: process.env.VITE_KEYCLOAK_BASE_URL,
    realm: process.env.VITE_KEYCLOAK_REALM,             
    clientId: process.env.VITE_KEYCLOAK_CLIENT_ID,  
});

export default keycloak;