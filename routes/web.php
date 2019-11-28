<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

// Client
Route::post('/register', 'ClientController@register')->name('register');
Route::get('/getServerKey', 'ClientController@getServerKey')->name('getServerKey');
Route::post('/storeSecret', 'ClientController@storeSecret')->name('storeSecret');
Route::get('/getSecret', 'ClientController@getSecret')->name('getSecret');

// Generate Key
Route::get('/generateKey', 'ClientController@generateKey')->name('generateKey');

// Test
Route::get('/test', 'ClientController@test')->name('test');
Route::get('/', function () {
    return view('welcome');
});
