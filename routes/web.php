<?php

use Illuminate\Support\Facades\Route;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Auth;
use App\Models\User;


Route::get('/', function () {
    return view('welcome');
});

Route::get('/login', function () {
    return Socialite::driver('keycloak')->redirect();
})->name('login');

Route::get('/callback', function () {
    $keycloakUser = Socialite::driver('keycloak')->user();

    // Find or create a local user
    $user = User::updateOrCreate(
        ['keycloak_id' => $keycloakUser->getId()],
        [
            'name' => $keycloakUser->getName(),
            'email' => $keycloakUser->getEmail(),
        ]
    );

    // Log the user into Laravel
    Auth::login($user);

    // Generate an authorization token (optional, if using Laravel Passport)
    $token = $user->createToken('authToken')->accessToken;

    return redirect('/home')->with('token', $token);
});

Route::get('/home', function () {
    return 'Welcome, ' . Auth::user()->name;
});

// Route::middleware(['auth'])->group(function () {
//     Route::get('/home', 'HomeController@index');
//     Route::get('/admin', 'AdminController@index')->middleware('role:master');
//     Route::get('/editor', 'EditorController@index')->middleware('role:editor');
//     Route::get('/client', 'ClientController@index')->middleware('role:client');
//     Route::get('/admin', 'AdminController@index')->middleware(['auth', 'role:master']);
//     Route::get('/editor', 'EditorController@index')->middleware(['auth', 'role:editor']);
//     Route::get('/client', 'ClientController@index')->middleware(['auth', 'role:client']);

// });
