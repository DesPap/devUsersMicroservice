<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AppController;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Auth;
use App\Models\User;


// Route::get('/', function () {
//     return view('welcome');
// });

// all routes except API routes render the React application
// Route::get('/{any}', [AppController::class, 'index'])->where('any', '.*');

Route::get('/{any}', function () {
    return view('app'); // This points to the React view
})->where('any', '.*');