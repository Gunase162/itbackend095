<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;



class UsersSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        DB::table('users')->delete();
        $data = [
            [
                'name' => 'Gunphirom Lemnui',
                'email' => 'kanspy11@gmail.com',
                'password' => Hash::make('123456'),
                'role' => 'TSU',
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),  
            ],
            [
                'name' => 'Gunphirom Lemnui',
                'email' => '622021095@tsu.ac.th',
                'password' => Hash::make('123456'),
                'role' => 'TSU',
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),  
            ],
            [
                'name' => 'Gunphirom Lemnui',
                'email' => 'kanspy11@yahoo.com',
                'password' => Hash::make('123456'),
                'role' => 'TSU',
                'created_at' => Carbon::now(),
                'updated_at' => Carbon::now(),  
            ],
        ];

        DB::table('users')->insert($data);
    }
}
