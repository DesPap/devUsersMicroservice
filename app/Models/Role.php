<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Role extends Model
{
    use HasFactory;

    protected $table = 'client_role';

    protected $primaryKey = 'id';

    protected $fillable = [
        'name',
        'client_id', 
        'description',
        // Add other columns that might be in Keycloak's role table
    ];

    public function users()
    {
        return $this->belongsToMany(User::class, 'user_role_mapping', 'role_id', 'user_id');
    }
}
