<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class MasterController extends Controller
{
    public function indexMaster()
    {
        return response()->json(['message' => 'Welcome, Master!']);
    }
}