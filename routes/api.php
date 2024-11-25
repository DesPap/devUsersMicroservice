<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\MasterController;
use App\Http\Controllers\EditorController;
use App\Http\Controllers\ClientController;



Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

// Route::post('auth/login', [AuthController::class, 'authenticate']);
Route::post('auth/login', [AuthController::class, 'authenticate']);
Route::post('/auth/register', [AuthController::class, 'registerUser']);
Route::post('auth/logout', [AuthController::class, 'logout']);
Route::get('after_logout', function () {
    $message = session('message', 'Determining a Valid post logout redirect URI in Keycloak Client Settings ');
    return response()->json(['message' => $message]);
})->name('after.logout');

Route::get('auth/callback', [AuthController::class, 'callback']);
Route::post('/auth/unregister', [AuthController::class, 'unregisterUser']);

