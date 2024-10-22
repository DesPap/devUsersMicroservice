<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class EditorController extends Controller
{
    public function indexEditor()
    {
        return response()->json(['message' => 'Welcome, Editor!']);
    }
}