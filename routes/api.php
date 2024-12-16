<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;


Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::get('/auth/check', [AuthController::class, 'checkAuthStatus']);
Route::post('auth/login', [AuthController::class, 'authenticate']);
Route::post('/auth/register', [AuthController::class, 'registerUser']);

Route::middleware(['keycloak'])->group(function ()
{
Route::post('auth/check', [AuthController::class, 'checkAuthStatus']);
Route::post('auth/logout', [AuthController::class, 'logout']);
Route::get('after_logout', function () {
    $message = session('message', 'Determining a Valid post logout redirect URI in Keycloak Client Settings ');
    return response()->json(['message' => $message]);
})->name('after.logout');


Route::post('/auth/unregister', [AuthController::class, 'unregisterUser']);
});
