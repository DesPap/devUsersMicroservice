<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory;

    protected $table = 'user_entity';

    protected $primaryKey = 'id';

    protected $fillable = ['username', 'email', 'email_constraint', 'email_verified', 
    'enabled', 'federation_link', 'first_name', 'last_name', 'realm_id', 'username', 
    'created_timestamp', 'service_account_client_link', 'not_before'];

    protected $hidden = ['password'];

    //user_role_mapping links users to roles.
    public function roles()
    {
        return $this->belongsToMany(Role::class, 'user_role_mapping', 'user_id', 'role_id');
    }

    //links users to groups
    public function clients()
    {
        return $this->belongsToMany(Client::class, 'user_id');
    }
}