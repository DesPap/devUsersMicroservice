<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RoleMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next  string  $role
     */
    // public function handle(Request $request, Closure $next, string $role): Response
    // {
    //     // Get the authenticated user
    //     $user = Auth::user();

    //     // Check if the user is authenticated and has the required role
    //     if (!$user || !$user->hasRole($role)) {
    //         // Optionally, redirect the user or return an error response
    //         return redirect('/')->with('error', 'You do not have access to this page.');
    //     }

    //     return $next($request);
    // }
}
