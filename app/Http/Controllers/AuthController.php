<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    // Register a new user
    public function register(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
            'username' => 'required|unique:users',
        ]);

        $user = User::create([
            'id' => Str::uuid(),
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'username' => $validated['username'],
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json(['message' => 'Registration successful', 'token' => $token], 201);
    }

    // Login
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if (!Auth::attempt($credentials)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        $user = Auth::user();
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json(['message' => 'Login successful', 'token' => $token], 200);
    }

    // Logout
    public function logout()
    {
        Auth::user()->tokens()->delete();
        return response()->json(['message' => 'Logout successful'], 200);
    }
}