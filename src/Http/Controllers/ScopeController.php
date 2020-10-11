<?php

namespace Zivot\Mongodb\Passport\Http\Controllers;

use Zivot\Mongodb\Passport\Passport;

class ScopeController
{
    /**
     * Get all of the available scopes for the application.
     *
     * @return \Illuminate\Support\Collection
     */
    public function all()
    {
        return Passport::scopes();
    }
}
