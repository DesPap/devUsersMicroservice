<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Middleware\KeycloakMiddleware;


Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::post('auth/login', [AuthController::class, 'authenticate']);
Route::post('/auth/register', [AuthController::class, 'registerUser']);
Route::post('auth/check', [AuthController::class, 'checkAuthStatus']);   // explicitly check if the user is authenticated. Validate the token with Keycloak. Responds if the user is authenticated. Verify authentication on protected routes
Route::post('/auth/resend-verification-email', [AuthController::class, 'resendVerificationEmail']);
Route::post('auth/logout', [AuthController::class, 'logout']);

Route::middleware([KeycloakMiddleware::class])->group(function ()
{
    Route::get('/auth/user-info', [AuthController::class, 'getUserInfo']);   // fetch the latest user info and roles.
    
    Route::get('after_logout', function () {
        $message = session('message', 'Determining a Valid post logout redirect URI in Keycloak Client Settings ');
        return response()->json(['message' => $message]);
    })->name('after.logout');


    Route::post('/auth/unregister', [AuthController::class, 'unregisterUser']);
});
