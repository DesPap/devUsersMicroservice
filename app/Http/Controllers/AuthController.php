<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Http\Request;

class AuthController extends Controller
/**
 * getUserInfo: fetch the latest user info and roles.
 * checkAuthStatus: Validates the token with Keycloak and responds if the user is authenticated.
 * authenticate: Handles login in keycloak, checking if the user exists in the local db.
 * registerUser: Registers a new user in Keycloak and saves the data locally.
 * assignRoleToUser: Fetches roles from Keycloak and stores them locally, with Keycloak handling role permissions.
 * unregisterUser: Deactivates a user locally and removes them from Keycloak.
 */

 {
    /**
     * getUserInfo: fetch the latest user info and roles.
     */

     public function getUserInfo(Request $request)
     {
         $keycloakUser = $request->keycloak_user; // Retrieved from middleware
         return response()->json([
             'user' => [
                 'username' => $keycloakUser['preferred_username'],
                 'email' => $keycloakUser['email'],
                 'name' => $keycloakUser['name'] ?? null,
                 'roles' => $keycloakUser['roles'] ?? ['user'],
             ],
         ]);
     }


    /**
     *  Validate the token with Keycloak and responds if the user is authenticated. Verify authentication on protected routes
     */
    public function checkAuthStatus(Request $request)
    {
        $token = $request->bearerToken();
    
        if (!$token) {
            return response()->json(['authenticated' => false, 'message' => 'Token missing'], 401);
        }
    
        try {
            // Validate the token with Keycloak's /userinfo endpoint
            $response = Http::withToken($token)->get(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/userinfo');
    
            if ($response->failed()) {
                return response()->json(['authenticated' => false, 'error' => 'Invalid access token'], 401);
            }
    
            // Token is valid, return success
            return response()->json(['authenticated' => true, 'user' => $response->json()]);
        } catch (\Exception $e) {
            Log::error('Error validating token with Keycloak: ' . $e->getMessage());
    
            return response()->json(['authenticated' => false, 'error' => 'Failed to validate token'], 500);
        }
    }

    /**
     * Handle authentication and token exchange in order for the user to login.
     */
    public function authenticate(Request $request)
    {
        $request->validate([
            'username' => 'required|string',
            'password' => 'required|string',
            'client_id' => 'required|string',
            'client_secret' => 'required|string',
        ]);
    
        $username = $request->input('username');
        $password = $request->input('password');
        $clientId = $request->input('client_id');
        $clientSecret = $request->input('client_secret');
    
        // Validate client credentials against config
        if ($clientId !== config('keycloak.client_id') || $clientSecret !== config('keycloak.client_secret')) {
            Log::error('Invalid client credentials provided.');
            return response()->json(['error' => 'Invalid client credentials.'], 401);
        }
    
        try {
            // Verify user credentials in Keycloak
            $response = Http::asForm()->post(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/token', [
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'grant_type' => 'password',
                'username' => $username,
                'password' => $password,
                'scope' => 'openid profile email',
            ]);


            if ($response->failed()) {
                // Step 1: Obtain admin token to search for user existence
                $adminResponse = Http::asForm()->post(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/token', [
                    'client_id' => $clientId,
                    'client_secret' => $clientSecret,
                    'grant_type' => 'client_credentials',
                ]);
    
                if ($adminResponse->failed()) {
                    Log::error('Failed to obtain admin token.');
                    return response()->json([
                        'status' => 'keycloak_error',
                        'message' => 'Error communicating with Keycloak.'
                    ], 500);
                }
    
                $adminToken = $adminResponse->json()['access_token'];
    
                // Step 2: Search for the user in Keycloak
                $userSearchResponse = Http::withToken($adminToken)->get(
                    config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users',
                    ['username' => $username]
                );
                // If user does not exist (status is checked by React)
                if (empty($userSearchResponse->json())) {
                    return response()->json([
                        'status' => 'user_not_found',
                        'message' => 'User does not exist.',
                    ]);
                }
    
                // If user exists but password is wrong (status is checked by React)
                return response()->json([
                    'status' => 'invalid_password',
                    'message' => 'Invalid password.',
                ]);
            }
    
            // Retrieve token and user info from Keycloak (user ID, roles, etc.)
            $tokenData = $response->json();
    
            // Fetch user details from Keycloak
            $userInfoResponse = Http::withHeaders([
                'Authorization' => 'Bearer ' . $tokenData['access_token'],
            ])->get(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/userinfo');
    
            if ($userInfoResponse->failed()) {
                Log::error('Failed to fetch user info from Keycloak: ' . $userInfoResponse->body());
                return response()->json(['error' => 'Unable to fetch user information.'], 500);
            }
    
            $userInfo = $userInfoResponse->json();

            // Cache tokens
            Cache::put("user_{$username}_access_token", $tokenData['access_token'], now()->addSeconds($tokenData['expires_in']));
            Cache::put("user_{$username}_refresh_token", $tokenData['refresh_token'], now()->addSeconds($tokenData['refresh_expires_in']));
    
            // Ensure the user exists in the local database or create them
            $localUser = User::updateOrCreate(
                ['keycloak_id' => $userInfo['sub']],
                [
                    'username' => $userInfo['preferred_username'],
                    'email' => $userInfo['email'],
                    'first_name' => $userInfo['given_name'] ?? null,
                    'last_name' => $userInfo['family_name'] ?? null,
                    'is_active' => true,
                    'role' => $userInfo['roles'][0] ?? 'user',
                ]
            );
    
            // Log the user in locally
            Auth::guard()->setUser($localUser);
    
            return response()->json([
                'authenticated' => true,
                'roles' => $userInfo['resource_access']['account']['roles'] ?? 'user',
                'user' => [
                    'username' => $userInfo['preferred_username'],
                    'email' => $userInfo['email'],
                    'name' => $userInfo['name'] ?? null,
                ],
            ]);
        } catch (\Exception $e) {
            Log::error('Error during authentication: ' . $e->getMessage());
            return response()->json(['error' => 'Authentication failed. Please try again.'], 500);
        }
    }


    /**
     * Register a new user in Keycloak and store in the local DB.
     */
    public function registerUser(Request $request)
    {
        $request->validate([
            'client_id' => 'required|string',
            'client_secret' => 'required|string',
            'username' => 'required|string',
            'password' => 'required|string',
            'isInitialRegistration' => 'required|boolean', // Indicates initial registration or profile update
            'first_name' => 'nullable|string',
            'last_name' => 'nullable|string',
            'country' => 'nullable|string',
            'address' => 'nullable|string',
            'location' => 'nullable|string',
            'phone' => 'nullable|string',
            'company' => 'nullable|string',

        ]);

        $username = $request->input('username');
        $password = $request->input('password');
        $isInitialRegistration = $request->input('isInitialRegistration');
        $firstName = $request->input('first_name');
        $lastName = $request->input('last_name');
        $country = $request->input('country');
        $address = $request->input('address');
        $location = $request->input('location');
        $phone = $request->input('phone');
        $company = $request->input('company');

        
    
        try {
            // Validate client credentials and obtain admin token
            $adminToken = $this->getAdminToken($request);
            if (!$adminToken) {
                return response()->json(['error' => 'Invalid client credentials.'], 401);
            }

            // Check if the user already exists in Keycloak
            $existingUser = $this->getKeycloakUserIdByUsername($username, $adminToken);

            if ($isInitialRegistration) {
            //Initial Registration
            if ($existingUser) {
                Log::info('User already exists in Keycloak: ' . $username);
                return response()->json([
                    'status' => 'user_exists',
                    'message' => 'User already initially registered in Keycloak',
                    'user' => [
                        'username' => $username,
                        'email' => $username,
                        'first_name' => $firstName,
                        'last_name' => $lastName,
                    ]
                ], 200);
            }
    
            // Register the user in Keycloak
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $adminToken,
                'Content-Type' => 'application/json',
            ])->post(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users', [
                'username' => $username,
                'enabled' => true,
                'email' => $username,
                'credentials' => [
                    [
                        'type' => 'password',
                        'value' => $password,
                        'temporary' => false
                    ]
                ]
            ]);
    
            if ($response->failed()) {
                Log::error('Failed to create user in Keycloak: ' . $response->body());
                return response()->json(['error' => 'Failed to register user in Keycloak'], 500);
            }
    
            $keycloakUserId = $response->json()['id'] ?? $this->getKeycloakUserIdByUsername($username, $adminToken);
    
            // Assign 'user' role to the newly created user
            $roleResponse = $this->assignRoleToUser($adminToken, $keycloakUserId, 'user');
            if ($roleResponse->failed()) {
                Log::error('Failed to assign role to user in Keycloak: ' . $roleResponse->body());
                return response()->json(['error' => 'Failed to assign role to user'], 500);
            }

            // Store user locally
            $localUser = User::updateOrCreate(
                ['username' => $username],
                [
                    'keycloak_id' => $keycloakUserId,
                    'email' => $username,
                    'is_active' => true,
                    'role' => 'user' // default role
                ]
            );

            // Cache the token
            Cache::put("user_{$username}_access_token", $adminToken, now()->addMinutes(60));
    
            return response()->json(['message' => 'User registered successfully', 'user' => $localUser], 201);
    

        } else {
            // Account Settings Flow or Profile Completion
            if ($existingUser) {
                // Check if all fields are already filled
                $userDetailsResponse = Http::withHeaders([
                    'Authorization' => 'Bearer ' . $adminToken,
                ])->get(config('keycloak.base_url') . "/admin/realms/" . config('keycloak.realm') . "/users/{$existingUser}");

                if ($userDetailsResponse->failed()) {
                    Log::error('Failed to fetch user details from Keycloak: ' . $userDetailsResponse->body());
                    return response()->json(['error' => 'Failed to fetch user details from Keycloak'], 500);
                }

                $userDetails = $userDetailsResponse->json();
                $isComplete = isset($userDetails['firstName'], $userDetails['lastName'], $userDetails['attributes']['company']);

                if ($isComplete) {
                    // User registration is already complete
                    return response()->json([
                        'status' => 'registration_complete',
                        'message' => 'The registration of the user is already completed.',
                    ], 200);
                }
            }

            // Proceed to complete the registration
            $updateResponse = Http::withHeaders([
                'Authorization' => 'Bearer ' . $adminToken,
                'Content-Type' => 'application/json',
            ])->put(config('keycloak.base_url') . "/admin/realms/" . config('keycloak.realm') . "/users/{$existingUser}", [
                'firstName' => $firstName,
                'lastName' => $lastName,
                'attributes' => [
                    'company' => $company,
                ],
            ]);

            if ($updateResponse->failed()) {
                Log::error('Failed to update user in Keycloak: ' . $updateResponse->body());
                return response()->json(['error' => 'Failed to update user in Keycloak'], 500);
            }

            // Update local user record
            $localUser = User::where('username', $username)->first();
            $localUser->update([
                'first_name' => $firstName,
                'last_name' => $lastName,
                'company' => $company,
            ]);

            // Cache the token
            Cache::put("user_{$username}_access_token", $adminToken, now()->addMinutes(60));

            return response()->json([
                'status' => 'registration_completed',
                'message' => 'Registration completed successfully.',
            ], 201);
        }
        } catch (\Exception $e) {
            Log::error('Error during registration: ' . $e->getMessage());
            return response()->json(['error' => 'Registration failed'], 500);
        }
    }

    /**
     * Assign a role to a user in Keycloak.
     */
    private function assignRoleToUser($adminToken, $userId, $roleName)
    {
        // Retrieve the role ID from Keycloak
        $rolesResponse = Http::withHeaders([
            'Authorization' => 'Bearer ' . $adminToken,
        ])->get(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/roles/' . $roleName);

        if ($rolesResponse->failed() || empty($rolesResponse->json())) {
            Log::error('Failed to retrieve role from Keycloak: ' . $rolesResponse->body());
            throw new \Exception('Failed to retrieve role from Keycloak');
        }

        $role = $rolesResponse->json();

        // Assign the role to the user
        $assignRoleResponse = Http::withHeaders([
            'Authorization' => 'Bearer ' . $adminToken,
            'Content-Type' => 'application/json',
        ])->post(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users/' . $userId . '/role-mappings/realm', [
            [
                'id' => $role['id'],
                'name' => $role['name'],
            ]
        ]);

        return $assignRoleResponse;
    }

    /**
     * Get an admin token for Keycloak API interactions.
     */
    private function getAdminToken(Request $request)
    {
        $clientId = $request->input('client_id');
        $clientSecret = $request->input('client_secret');

        // Validate the provided client_id and client_secret against config values
        if ($clientId !== config('keycloak.client_id') || $clientSecret !== config('keycloak.client_secret')) {
            Log::error('Invalid client credentials provided.');
            return null;
        }

        $response = Http::asForm()->post(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/token', [
            'client_id' => config('keycloak.client_id'),
            'client_secret' => config('keycloak.client_secret'),
            'grant_type' => 'client_credentials',
        ]);

        if ($response->failed()) {
            Log::error('Failed to obtain admin token: ' . $response->body());
            return response()->json('Failed to obtain admin token from Keycloak', 500);
        }

        return $response->json()['access_token'];
    }

    /**
     * Unregister user in Keycloak and deactivate locally.
     */
    public function unregisterUser(Request $request)
    {
        $request->validate([
            'username' => 'required|string',
            'password' => 'required|string',
        ]);
    
        $username = $request->input('username');
        $password = $request->input('password');
    
        try {
            // Get the admin token
            $adminToken = $this->getAdminToken($request);
            if (!$adminToken) {
                return response()->json(['error' => 'Invalid client credentials.'], 401);
            }
    
            // Verify the user's credentials in Keycloak
            $validationResponse = Http::asForm()->post(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/token', [
                'client_id' => config('keycloak.client_id'),
                'client_secret' => config('keycloak.client_secret'),
                'grant_type' => 'password',
                'username' => $username,
                'password' => $password,
            ]);
    
            if ($validationResponse->failed()) {
                Log::error('Invalid username or password for user: ' . $username);
                return response()->json(['error' => 'Invalid username or password.'], 401);
            }
    
            // Get the user details from Keycloak
            $userSearchResponse = Http::withHeaders([
                'Authorization' => 'Bearer ' . $adminToken,
            ])->get(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users', [
                'username' => $username,
            ]);
    
            if ($userSearchResponse->failed() || empty($userSearchResponse->json())) {
                Log::error('User not found in Keycloak: ' . $username);
                return response()->json(['error' => 'User not found in Keycloak.'], 404);
            }
    
            $keycloakUserId = $userSearchResponse->json()[0]['id'];
    
            // Delete the user in Keycloak
            $deleteResponse = Http::withHeaders([
                'Authorization' => 'Bearer ' . $adminToken,
            ])->delete(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users/' . $keycloakUserId);
    
            if ($deleteResponse->failed()) {
                Log::error('Failed to delete user in Keycloak: ' . $deleteResponse->body());
                return response()->json(['error' => 'Failed to delete user in Keycloak.'], 500);
            }
    
            // Update the user's status locally
            $localUser = User::where('username', $username)->first();
            if ($localUser) {
                $localUser->update(['is_active' => false]);
            }
    
            return response()->json(['message' => 'User unregistered successfully.'], 200);
        } catch (\Exception $e) {
            Log::error('Error during user unregistration: ' . $e->getMessage());
            return response()->json(['error' => 'An error occurred while unregistering the user.'], 500);
        }
    }

    /**
     * Handle user logout and invalidate the Keycloak session.
     */
    public function logout(Request $request)
    {
        try {
            // Extract the token, client_id, and client_secret from the request
            $token = $request->input('token');
            $clientId = $request->input('client_id');
            $clientSecret = $request->input('client_secret');
    
            if (!$token || !$clientId || !$clientSecret) {
                return response()->json(['error' => 'Missing token or client credentials'], 400);
            }
    
            // Prepare the Keycloak logout URL
            $keycloakLogoutUrl = config('keycloak.external_base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/logout?' . http_build_query([
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'refresh_token' => $token,
            ]);
    
            return response()->json([
                'message' => 'Logout URL generated',
                'keycloak_logout_url' => $keycloakLogoutUrl,
            ]);

            return($keycloakLogoutUrl);
        } catch (\Exception $e) {
            Log::error('Failed to log out: ' . $e->getMessage());
            return response()->json(['error' => 'Failed to log out'], 500);
        }
    }


    //Previous Configuration in Keycloak

    // public function logout(Request $request)
    // {
    //     try {
    //         // Log out the user from Laravel
    //         Auth::logout();
    //         $request->session()->invalidate();
    //         $request->session()->regenerateToken();

    //         $idToken = session('keycloak_token')['id_token'] ?? null;

    //         if (!$idToken) {
    //             return response()->json(['error' => 'ID token not found'], 400);
    //         }
    
    //         $keycloakLogoutUrl = config('keycloak.external_base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/logout?' . http_build_query([
    //             'id_token_hint' => $idToken,
    //             'post_logout_redirect_uri' => url('api/after_logout'),
    //         ]);
    
    //         Log::info("Redirecting to Keycloak Logout URL: " . $keycloakLogoutUrl);
    
    //         return redirect($keycloakLogoutUrl);
    //     } catch (\Exception $e) {
    //         Log::error('Failed to log out: ' . $e->getMessage());
    //         return response()->json(['error' => 'Failed to log out. Please try again.'], 500);
    //     }
    // }



    /**
     * Get Keycloak user ID by username.
     */
    private function getKeycloakUserIdByUsername($username, $adminToken)
    {
        $response = Http::withHeaders([
            'Authorization' => 'Bearer ' . $adminToken,
        ])->get(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users', [
            'username' => $username,
        ]);

        if ($response->failed()) {
            Log::error('Failed to fetch user data from Keycloak: ' . $response->body());
            throw new \Exception('Failed to fetch user data from Keycloak');
        }

        $userData = $response->json();
        return $userData[0]['id'] ?? null;
    }
}


// {
//     /**
//      * Handle login, registration, and synchronization with Keycloak.
//      */
//     public function authenticate(Request $request)
//     {
//         $request->validate([
//             'client_id' => 'required|string',
//             'client_secret' => 'required|string',
//             'username' => 'required|string',
//             'password' => 'required|string',
//         ]);

//         $client_id = $request->input('client_id');
//         $client_secret = $request->input('client_secret');
//         $username = $request->input('username');
//         $password = $request->input('password');

//         // Validate client credentials against the configured values
//         if ($client_id !== config('keycloak.client_id') || $client_secret !== config('keycloak.client_secret')) {
//             Log::error("Invalid client credentials.");
//             return response()->json(['error' => 'Invalid client credentials.'], 401);
//         }

//         // Authenticate with Keycloak using the password grant type
//         $tokenData = $this->authenticateUserWithPasswordGrant($client_id, $client_secret, $username, $password);
//         if (isset($tokenData['error'])) {
//             return response()->json(['error' => $tokenData['error']], 401);
//         }
// //! if he exists in keycloak and gets a token, then save the data in the database (there could be a mistake and he is deleted)
//         // Check if the user exists locally
//         $localUser = User::where('username', $username)->first();
//         if (!$localUser) {
//             return response()->json(['error' => 'User not found. Please register.'], 404);
//         }

//         // Log the user in locally
//         Auth::guard()->setUser($localUser);

//         return response()->json([
//             'message' => 'Authenticated successfully',
//             'token_data' => $tokenData,
//         ]);
//     }

//     /**
//      * Register a new user in Keycloak and store in local DB, then get a token.
//      */
//     public function registerUser(Request $request)
//     {
//         $request->validate([
//             'client_id' => 'required|string',
//             'client_secret' => 'required|string',
//             'username' => 'required|string',
//             'password' => 'required|string',
//             'email' => 'required|string|email',
//         ]);

//         $client_id = $request->input('client_id');
//         $client_secret = $request->input('client_secret');
//         $username = $request->input('username');
//         $password = $request->input('password');
//         $email = $request->input('email');

//         try {
//             $adminToken = $this->getAdminToken();
            
//             // Register the user in Keycloak
//             $response = Http::withHeaders([
//                 'Authorization' => 'Bearer ' . $adminToken,
//                 'Content-Type' => 'application/json',
//             ])->post(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users', [
//                 'username' => $username,
//                 'enabled' => true,
//                 'email' => $email,
//                 'credentials' => [
//                     [
//                         'type' => 'password',
//                         'value' => $password,
//                         'temporary' => false
//                     ]
//                 ]
//             ]);

//             if ($response->failed()) {
//                 Log::error('Failed to create user in Keycloak: ' . $response->body());
//                 return ['status' => 'error', 'message' => 'Failed to register user in Keycloak.'];
//             }

//             $keycloakUserId = $response->json()['id'] ?? $this->getKeycloakUserIdByUsername($username, $adminToken);

//             // Store user locally
//             $localUser = User::updateOrCreate(
//             ['username' => $username],
//             [
//                 'keycloak_id' => $keycloakUserId,
//                 'email' => $email,
//                 'is_active' => true,
//                 'role' => 'user'
//             ]);

//             return response()->json(['message' => 'User registered successfully', 'user' => $localUser], 201);

//         } catch (\Exception $e) {
//             Log::error('Error during registration: ' . $e->getMessage());
//             return ['status' => 'registration failed', 'message' => 'Failed to register user in Keycloak.'];
//         }
//     }


//     private function getAdminToken() {
//         $response = Http::asForm()->post(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/token', [
//             'client_id' => config('keycloak.client_id'),
//             'client_secret' => config('keycloak.client_secret'),
//             'grant_type' => 'password',
//         ]);

//         if ($response->failed()) {
//             Log::error('Failed to obtain admin token: ' . $response->body());
//             throw new \Exception('Failed to obtain admin token from Keycloak');
//         }

//         return $response->json()['access_token'];
//     }

//     private function getKeycloakUserIdByUsername($username, $adminToken) {
//         $response = Http::withHeaders([
//             'Authorization' => 'Bearer ' . $adminToken,
//         ])->get(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users', [
//             'username' => $username,
//         ]);

//         if ($response->failed()) {
//             Log::error('Failed to fetch user data from Keycloak: ' . $response->body());
//             throw new \Exception('Failed to fetch user data from Keycloak');
//         }

//         $userData = $response->json();
//         return $userData[0]['id'] ?? null;
//     }

//     public function callback(Request $request)
//     {
//         $code = $request->input('code');

//         if (!$code) {
//             return response()->json(['error' => 'Authorization code not found'], 400);
//         }

//         // Exchange the authorization code for an access token
//         $response = Http::asForm()->post(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/token', [
//             'grant_type' => 'password',
//             'client_id' => config('keycloak.client_id'),
//             'client_secret' => config('keycloak.client_secret'),
//             'redirect_uri' => config('keycloak.redirect_uri'),
//             'code' => $code,
//         ]);

//         if ($response->failed()) {
//             return response()->json(['error' => 'Failed to exchange code for token'], 500);
//         }

//         $tokenData = $response->json();
//         return response()->json(['token_data' => $tokenData]);
//     }

//     /**
//      * Handle user logout.
//      */
//     public function logout(Request $request)
//     {
//         Auth::logout();
//         $request->session()->invalidate();
//         $request->session()->regenerateToken(); //After invalidating session, generate a new CSRF (Cross-Site Request Forgery) token for the next user session, to prevent vulnerabilities related to session fixation or CSRF attacks.

//         // Redirect to Keycloak logout endpoint
//         $keycloakLogoutUrl = config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/logout?' . http_build_query([
//             'post_logout_redirect_uri' => config('app.url'),
//         ]);

//         return response()->json(['message' => 'Logged out successfully', 'keycloak_logout_url' => $keycloakLogoutUrl]);
//     }


//     /**
//      * Unregister user in Keycloak and deactivate locally.
//      */
//     public function unregisterUser(Request $request)
//     {
//         $username = $request->input('username');
//         $localUser = User::where('username', $username)->first();

//         if (!$localUser) {
//             return response()->json(['error' => 'User ' . $username . ' not found locally'], 404);
//         }

//         try {
//             $response = Http::withHeaders([
//                 'Authorization' => 'Bearer ' . $this->getAdminToken(config('keycloak.client_id'), config('keycloak.client_secret'))
//             ])->delete(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users/' . $localUser->keycloak_id);

//             if ($response->failed()) {
//                 Log::error('Failed to delete user in Keycloak: ' . $response->body());
//                 return response()->json(['error' => 'Failed to delete user in Keycloak'], 500);
//             }

//             // Set the user as inactive locally
//             $localUser->update(['active' => false]);

//             return response()->json(['message' => 'User unregistered successfully'], 200);

//         } catch (\Exception $e) {
//             Log::error('Error during unregistration: ' . $e->getMessage());
//             return response()->json(['error' => 'Failed to unregister user. Try again.'], 500);
//         }
//     }

//     /**
//      * Check if user exists in Keycloak
//      */
//     public function userExistsInKeycloak($username) {
//         $response = Http::withHeaders([
//             'Authorization' => 'Bearer ' . $this->getAdminToken(),
//         ])->get(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users', [
//             'search' => $username,
//         ]);

//         return $response->successful() && !empty($response->json());
//     }

//     /**
//      * Authenticate the user with Keycloak using the password grant type.
//      */
//     private function authenticateUserWithPasswordGrant($client_id, $client_secret, $username, $password)
//     {
//         $response = Http::asForm()->post(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/token', [
//             'client_id' => $client_id,
//             'client_secret' => $client_secret,
//             'grant_type' => 'password',
//             'username' => $username,
//             'password' => $password,
//         ]);

//         if ($response->failed()) {
//             Log::error('Failed to authenticate user with password grant: ' . $response->body());
//             return ['error' => 'Authentication failed. Please check your credentials.'];
//         }

//         return $response->json();
//     }
// }






// namespace App\Http\Controllers;

// use App\Models\User;
// use Illuminate\Support\Facades\Auth;
// use Illuminate\Support\Facades\Http;
// use Illuminate\Support\Facades\Log;
// use Illuminate\Http\Request;

// class AuthController extends Controller
// {
//     /**
//      * Handle login or registration based on user existence.
//      */
//     public function authenticate(Request $request)
//     {
//         // Catch and validate the incoming request
//         $request->validate([
//             'client_id' => 'required|string',
//             'client_secret' => 'required|string',
//             'grant_type' => 'required|string',
//             'username' => 'required|string',
//             'password' => 'required|string',
//         ]);

//         // Extract data from the request
//         $client_id = $request->input('client_id');
//         $client_secret = $request->input('client_secret');
//         $grant_type = $request->input('grant_type');
//         $username = $request->input('username');
//         $password = $request->input('password');

//         // Validate the client_id and client_secret against the config values for security
//         if ($client_id !== config('keycloak.client_id') || $client_secret !== config('keycloak.client_secret')) {
//             Log::error("Invalid client credentials. client_id: {$client_id}, client_secret: {$client_secret}, grant_type: {$grant_type}  auth/login");
//             return response()->json(['error' => 'Invalid client credentials.'], 401);
//         }

//         try {
//             // Check if the user exists in the local database with the given password
//             $user = User::where('username', $username)->first();

//             if ($user) {
//                 // User exists locally. Check if exists in Keycloak
//                 if ($this->userExistsInKeycloak($client_id, $client_secret, $username)) {
//                     // User exists in Keycloak, proceed to get the token
//                     return $this->redirectToKeycloak();
//                 } else {
//                     return response()->json(['error' => 'User does not exist in Keycloak. Please register.'], 404);
//                 }
//             } else {
//                 // For registration, validate that email is provided
//                 $request->validate([
//                     'email' => 'required|string|email',
//                 ], [
//                     'email.required' => 'User not registered. Please provide the email address for registration.'
//                 ]);
//                 $email = $request->input('email');

//                 // User does not exist locally, proceed with registration
//                 return $this->registerUser($client_id, $client_secret, $username, $password, $email);
//             }
//         } catch (\Exception $e) {
//             Log::error('Error during authentication: ' . $e->getMessage() . 'auth/login');
//             return response()->json(['error' => 'Error during authentication. Please try again.'], 500);
//         }
//     }

//     /**
//      * Register a new user in Keycloak and store in local DB, then get a token.
//      */
//     private function registerUser($client_id, $client_secret, $username, $password, $email)
//     {
//         try {
//             // Register the user in Keycloak
//             $response = Http::withHeaders([
//                 'Authorization' => 'Bearer ' . $this->getAdminToken($client_id, $client_secret),
//                 'Content-Type' => 'application/json',
//             ])->post(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users', [
//                 'username' => $username,
//                 'enabled' => true,
//                 'email' => $email,
//                 'credentials' => [
//                     [
//                         'type' => 'password',
//                         'value' => $password,
//                         'temporary' => false
//                     ]
//                 ]
//             ]);

//             if ($response->failed()) {
//                 Log::error('Failed to create user in Keycloak: ' . $response->body() . 'auth/login');
//                 return response()->json(['error' => 'Failed to create user in Keycloak'], 500);
//             }

//             // Store the user in the local database
//             $user = User::create([
//                 'keycloak_id' => $response->json()['id'],
//                 'username' => $username,
//                 'email' => $email,
//             ]);

//             // After registration, redirect the user to Keycloak login.
//             return $this->redirectToKeycloak();
//         } catch (\Exception $e) {
//             Log::error('Error during user registration: ' . $e->getMessage() . 'auth/login');
//             return response()->json(['error' => 'An error occurred during registration. Please try again.'], 500);
//         }
//     }

//     /**
//      * Helper method to check if a user exists in Keycloak.
//      */
//     private function userExistsInKeycloak($client_id, $client_secret, $username)
//     {
//         $response = Http::withHeaders([
//             'Authorization' => 'Bearer ' . $this->getAdminToken($client_id, $client_secret),
//         ])->get(config('keycloak.base_url') . '/admin/realms/' . config('keycloak.realm') . '/users', [
//             'search' => $username,
//         ]);

//         Log::info('Keycloak User Search Response:', ['response' => $response->json()]);
//         return $response->successful() && !empty($response->json());
//     }

//     /**
//      * Get an admin token for Keycloak API interactions like registration.
//      */
//     private function getAdminToken($client_id, $client_secret)
//     {
//         $response = Http::asForm()->post(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/token', [
//             'client_id' => $client_id,
//             'client_secret' => $client_secret,
//             'grant_type' => 'client_credentials',
//         ]);

//         if ($response->failed()) {
//             Log::error('Failed to obtain admin token from Keycloak: ' . $response->body() . 'auth/login');
//             throw new \Exception('Failed to obtain admin token from Keycloak');
//         }

//         return $response->json()['access_token'];
//     }


//     /**
//      * Redirect to Keycloak for user login.
//      * After user enters credential on Keycloak's page, Keycloak redirects to Laravel app (to redirect_uri) with auth code 
//      */
    
//     public function redirectToKeycloak()
//     {
//         try {
//             $authUrl = config('keycloak.external_base_url') . '/realms/' . ltrim(config('keycloak.realm'), '/') . '/protocol/openid-connect/auth?' . http_build_query([
//                 'client_id' => config('keycloak.client_id'),
//                 'redirect_uri' => config('keycloak.redirect_uri'),
//                 'response_type' => 'code',
//                 'scope' => 'openid email profile',
//             ]);

//             return redirect($authUrl);
//         } catch (\Exception $e) {
//             Log::error('Failed to redirect to Keycloak: ' . $e->getMessage() . 'auth/login');
//             return response()->json(['error' => 'Failed to initiate login with Keycloak. Please try again.'], 500);
//         }
//     }


//     /**
//      * Handles the Keycloak callback to exchange the auth code for tokens.
//      * 
//      * Gets the auth code from Keycloak and sends a post to Keycloak's token endpoint,
//      * to exchange the auth code with an access_token and refresh_token.
//      * Keycloak returns the access_token and is stored in session.
//      * User infos are stored on the table user and user is loged in
//      */

//     public function handleKeycloakCallback(Request $request)

//     {
//         try {
//             // Check if the authorization code exists in the request
//             $code = $request->input('code');
        
//             if (!$code) {
//                 return response()->json(['error' => 'Authorization code not found'], 400);
//             }
        
//             // Prepare the Keycloak token exchange request
//             $response = Http::asForm()->post(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/token', [
//                 'grant_type' => 'authorization_code',
//                 'client_id' => config('keycloak.client_id'),
//                 'client_secret' => config('keycloak.client_secret'),
//                 'redirect_uri' => config('keycloak.redirect_uri'),
//                 'code' => $code,
//             ]);
        
//             if ($response->failed()) {
//                 Log::error('Failed to communicate with Keycloak during token exchange. Response: ' . $response->body() . 'auth/callback');
//                 return response()->json(['error' => 'Failed to communicate with Keycloak'], 500);
//             }

//             // Decode the token response
//             $tokenData = $response->json();
        
//             if (!isset($tokenData['access_token'])) {
//                 Log::error('Access token missing in the response from Keycloak. auth/callback');
//                 return response()->json(['error' => 'Failed to obtain access token'], 400);
//             }
        
//             // Decode the access token to get user info
//             $decodedToken = json_decode(base64_decode(explode('.', $tokenData['access_token'])[1]), true);
        
//             if (!$decodedToken) {
//                 Log::error('Failed to decode access token from Keycloak. auth/callback');
//                 return response()->json(['error' => 'Failed to decode access token. Please try again.'], 500);
//             }

//             // Store the user and the token data in the session
//             session(['keycloak_token' => $tokenData]);

//             // Retrieve or create the user in the database
//             $user = User::updateOrCreate(
//                 ['keycloak_id' => $decodedToken['sub']],
//                 [
//                     'email' => $decodedToken['email'],
//                     'username' => $decodedToken['preferred_username'],
//                 ]
//             );
        
//         // Manually set the user for the current request
//             auth()->guard('keycloak')->setUser($user);
            
//             return response()->json([
//                 'message' => 'Authenticated successfully',
//                 'token_data' => $tokenData,
//             ]);

//         } catch (\Exception $e) {
//             Log::error('Error during login: ' . $e->getMessage() . 'auth/callback');
//             return response()->json(['error' => 'An error occurred during login. Please try again.'], 500);
//         }
//     }

//     /**
//      * Logs out the user from Laravel, then from Keycloak and returns a message 
//      */

//     public function logout(Request $request)
//     {
//         try{
//             // Log out the user from Laravel
//             Auth::logout();
//             $request->session()->invalidate(); //clear all session data
//             $request->session()->regenerateToken(); //generate a new CSRF token to protect against session fixation attacks

//             session()->flash('message', 'Logged out successfully');

//             // Prepare the Keycloak logout URL and redirect it to /after_logout route, for the message
//             $keycloakLogoutUrl = config('keycloak.external_base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/logout?' . http_build_query([
//                 'id_token_hint' => session('keycloak_token')['id_token'] ?? '',
//                 'post_logout_redirect_uri' => url('api/after_logout'),
//             ]);                  
//             // config('keycloak.external_base_url') . '/realms/' . ltrim(config('keycloak.realm'), '/') . '/protocol/openid-connect/auth?' . http_build_query

//             // return redirect($keycloakLogoutUrl);
//             return response()->json([
//                 'message' => 'Redirecting to Keycloak for logout',
//                 'keycloak_logout_url' => $keycloakLogoutUrl
//             ]);

//         } catch (\Exception $e) {
//             Log::error('Failed to log out from Laravel.' . $e->getMessage());
//             return response()->json(['error' => 'Failed to log out from Laravel. Please try again.' . $e->getMessage() . '/after_logout'], 500);
//         }
        
//     }
// }