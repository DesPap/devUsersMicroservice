<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class KeycloakMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => 'Access token not provided'], 401);
        }

        try {
            // Verify token with Keycloak
            $response = Http::withToken($token)->get(config('keycloak.base_url') . '/realms/' . config('keycloak.realm') . '/protocol/openid-connect/userinfo');

            if ($response->failed()) {
                return response()->json(['error' => 'Invalid access token'], 401);
            }

            // Attach user information from Keycloak to the request
            $user = $response->json();
            $request->merge(['keycloak_user' => $user]);

            return $next($request);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to validate token'], 500);
        }
    }
}