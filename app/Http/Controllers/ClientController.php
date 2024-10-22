<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ClientController extends Controller
{
    public function indexClient()
    {
        return response()->json(['message' => 'Welcome, Client!']);
    }
}