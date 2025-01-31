<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class KeycloakMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $username = $request->session()->get('username'); // Get the username from session
    
        if (!$username) {
            return response()->json(['error' => 'User  not authenticated'], 401);
        }
    
        $accessToken = cache()->get("user_{$username}_access_token");
        $refreshToken = cache()->get("user_{$username}_refresh_token");
    
        if (!$accessToken) {
            return response()->json(['error' => 'Access token not available'], 401);
        }
    
        try {
            // Validate the access token with Keycloak
            $response = Http::withToken($accessToken)
                ->get(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/userinfo');
    
            if ($response->failed()) {
                // If token is invalid, attempt to refresh it
                if ($refreshToken) {
                    $refreshResponse = Http::asForm()->post(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/token', [
                        'client_id' => config('keycloak.client_id'),
                        'client_secret' => config('keycloak.client_secret'),
                        'grant_type' => 'refresh_token',
                        'refresh_token' => $refreshToken,
                    ]);
    
                    if ($refreshResponse->successful()) {
                        $newTokenData = $refreshResponse->json();
                        cache()->put("user_{$username}_access_token", $newTokenData['access_token'], now()->addSeconds($newTokenData['expires_in']));
                        cache()->put("user_{$username}_refresh_token", $newTokenData['refresh_token'], now()->addSeconds($newTokenData['refresh_expires_in']));
                    } else {
                        return response()->json(['error' => 'Failed to refresh token'], 401);
                    }
                } else {
                    return response()->json(['error' => 'Refresh token not available'], 401);
                }
            }
    
            // Attach user information from Keycloak to the request
            $user = $response->json();
            $request->merge(['keycloak_user' => $user]);
    
            return $next($request);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to validate token'], 500);
        }
    }
    
    
    
    
    // {
    //     $token = $request->bearerToken();

    //     if (!$token) {
    //         return response()->json(['error' => 'Access token not provided'], 401);
    //     }

    //     try {
    //         // Verify token with Keycloak
    //         $response = Http::withToken($token)->get(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/userinfo');

    //         if ($response->failed()) {
    //             return response()->json(['error' => 'Invalid access token'], 401);
    //         }

    //         // Attach user information from Keycloak to the request
    //         $user = $response->json();
    //         $request->merge(['keycloak_user' => $user]);

    //         return $next($request);
    //     } catch (\Exception $e) {
    //         return response()->json(['error' => 'Failed to validate token'], 500);
    //     }


    //     {
    //         $token = $request->bearerToken();
    
    //         if (!$token) {
    //             return response()->json(['authenticated' => false, 'message' => 'Token missing'], 401);
    //         }
    
    //         $response = Http::withHeaders(['Authorization' => 'Bearer ' . $token])
    //             ->post(config('keycloak.introspection_endpoint'), [
    //                 'token' => $token,
    //                 'client_id' => config('keycloak.client_id'),
    //                 'client_secret' => config('keycloak.client_secret'),
    //             ]);
    
    //         if ($response->failed() || !$response->json('active')) {
    //             return response()->json(['authenticated' => false, 'message' => 'Invalid token'], 401);
    //         }
    
    //         return $next($request);
    //     }
    // }
}