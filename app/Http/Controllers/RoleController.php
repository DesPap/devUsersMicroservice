<?php

namespace App\Http\Controllers;

use App\Models\Role;
use App\Models\User;
use Illuminate\Http\Request;

class RoleController extends Controller
{
    // Get all roles
    public function getRoles()
    {
        $roles = Role::all();
        return response()->json($roles, 200);
    }

    // Assign a role to a user
    public function assignRole(Request $request)
    {
        $validated = $request->validate([
            'user_id' => 'required|exists:users,id',
            'role_id' => 'required|exists:roles,id',
        ]);

        $user = User::findOrFail($validated['user_id']);
        $user->roles()->attach($validated['role_id']);

        return response()->json(['message' => 'Role assigned successfully'], 200);
    }
}