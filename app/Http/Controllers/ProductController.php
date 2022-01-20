<?php

namespace App\Http\Controllers;

use App\Models\Product;
use Illuminate\Http\Request;

class ProductController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        //
        $result = ['name' => 'index', 'payload'=>Product::all()];
        return $result;
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
        $fields = $request->validate([
            'product_name' => 'required',
            'product_type' => 'required|integer',
            'price' => 'required',
        ]);

        $product = product::create([
            'product_name' => $fields['product_name'],
            'product_type' => $fields['product_type'],
            'price' => $fields['price'],
        ]);   

        $result = ['name' => 'store', 'payload'=>$product];
        return $result;
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Models\Product  $product
     * @return \Illuminate\Http\Response
     */
    public function show( $id)
    {
        //
        $result = ['name' => 'show', 'payload'=>Product::where('product_id',$id)->first()];
        return $result;
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\Product  $product
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, Product $product)
    {
        //
        $result = ['name' => 'update', 'payload'=>$request->all()];
        return $result;
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Models\Product  $product
     * @return \Illuminate\Http\Response
     */
    public function destroy( $id)
    {
        //
        $product = Product::where('id', $id);
        $product->delete();
        $result = ['name' => 'destroy', 'payload'=>'Deleted.'];
        return $result;
    }
}
