<?php

namespace App\Http\Controllers;

use App\Models\Customer;
use Illuminate\Http\Request;

class CustomerController extends Controller
{
    //list the customers

    public function index()
    {
        $customers = Customer::all();
        return response()->json($customers);
    }

    //store new customer data
    public function store(Request $request) {
        $validatedData = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string'

        ]);

        $customer = Player::create($validatedData);
        return response()->json($customer, 201);
    }

    //display the resource
    public function show(Customer $customer) {
        return response()->json($customer);
    }

    //update the resourse
    public function update(Request $request, Customer $customer) {
        $validatedData = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string'
        ]);

        $customer->update($validatedData);
        return responce()->json($customer, 200);

    }

    //remove the resource
    public function destroy(Customer $customer) {
        $customer->delete();
        return response()->json(null, 204);
    }
}