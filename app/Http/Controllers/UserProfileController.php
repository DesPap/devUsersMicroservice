<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class UserProfileController extends Controller
{
    // Get user profile
    public function profile()
    {
        $user = Auth::user();
        return response()->json($user, 200);
    }

    // Update user profile
    public function update(Request $request)
    {
        $user = Auth::user();

        $validated = $request->validate([
            'username' => 'sometimes|unique:users',
            'avatar_url' => 'sometimes|url',
        ]);

        $user->update($validated);
        return response()->json(['message' => 'Profile updated successfully'], 200);
    }
}