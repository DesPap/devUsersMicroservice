<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->uuid('id')->primary(); // Using UUID for primary key
            $table->string('keycloak_id')->unique()->nullable();
            $table->string('email')->unique();
            $table->string('password');
            $table->string('username')->unique();
            // $table->text('avatar_url')->nullable(); // Avatar URL can be nullable
            $table->timestamps(); // created_at and updated_at
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('user');
    }
};
