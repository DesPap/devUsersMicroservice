<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    use Notifiable;

    protected $table = 'user';

    protected $primaryKey = 'id';

    protected $fillable = ['keycloak_id', 'email', 'username', 'role', 'is_active', 'first_name', 
    'last_name', 'country', 'address', 'location', 'phone', 'company', 'is_initial_registration'];

    // Method to check if user has a specific role
    public function hasRole($role)
    {
        // roles are included in the JWT token and stored in a decoded_token attribute
        $roles = $this->decoded_token['roles'] ?? [];

        return in_array($role, $roles);
    }

    // Accessor to get decoded JWT token from the session
    public function getDecodedTokenAttribute()
    {
        return session('keycloak_token');
    }
}