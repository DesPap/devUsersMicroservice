<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Client extends Model
{
    use HasFactory;

    protected $table = 'client';

    protected $primaryKey = 'id';

    protected $fillable = [
        'client_id', 
        'client_name',
        'realm_id'
    ];

    public function roles()
    {
        return $this->hasMany(Role::class, 'client_id');
    }

    public function users()
    {
        return $this->belongsTo(User::class, 'user_id');
    }
}
