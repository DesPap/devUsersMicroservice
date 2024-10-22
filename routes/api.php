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

Route::get('auth/login', [AuthController::class, 'redirectToProvider'])->name('auth.login');
Route::get('auth/callback', [AuthController::class, 'handleProviderCallback'])->name('auth.callback');
Route::post('auth/logout', [AuthController::class, 'logout'])->name('auth.logout');

Route::middleware(['auth', 'checkrole:admin'])->group(function () {
    Route::get('/admin', [AdminController::class, 'indexAdmin'])->name('admin.dashboard');
});

Route::middleware(['auth', 'checkrole:master'])->group(function () {
    Route::get('/master', [MasterController::class, 'indexMaster'])->name('master.dashboard');
});

Route::middleware(['auth', 'checkrole:editor'])->group(function () {
    Route::get('/editor', [EditorController::class, 'indexEditor'])->name('editor.dashboard');
});

Route::middleware(['auth', 'checkrole:client'])->group(function () {
    Route::get('/client', [ClientController::class, 'indexClient'])->name('client.dashboard');
});