<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function redirectToProvider()
    {
        return redirect()->route('auth.callback');
    }

    public function handleProviderCallback(Request $request)
    {
        // Get the user info from the decoded JWT token
        $decodedToken = $request->user()->token; // Adjust based on the JWT structure

        $user = User::updateOrCreate(
            ['keycloak_id' => $decodedToken['sub']],
            [
                'email' => $decodedToken['email'],
                'username' => $decodedToken['preferred_username'],
            ]
        );

        // Store the decoded token in session
        session(['keycloak_token' => $decodedToken]);

        Auth::login($user);

        return response()->json(['message' => 'Authenticated successfully']);
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        return response()->json(['message' => 'Logged out successfully']);
    }
}