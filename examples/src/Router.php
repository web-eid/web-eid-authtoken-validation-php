<?php

/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* App router */

class Router
{
    public function init()
    {

        $router = new AltoRouter();
        $router->setBasePath("");

        // Page routes
        $router->map("GET", "/", ["controller" => "Pages", "method" => "login"]);
        $router->map("GET", "/logout", ["controller" => "Auth", "method" => "logout"]);
        // Endpoint for extension errors logging
        $router->map("POST", "/logger", ["controller" => "LogWriter", "method" => "add"]);

        // Web eID routes
        $router->map("GET", "/nonce", ["controller" => "Auth", "method" => "getNonce"]);
        $router->map("POST", "/validate", ["controller" => "Auth", "method" => "validate"]);

        // Allow route only for authenticated users
        if (isset($_SESSION["auth-user"])) {
            $router->map("GET", "/welcome", ["controller" => "Pages", "method" => "welcome"]);
        }

        $match = $router->match();

        if (!$match) {
            // Redirect to login
            header("Location: /");
            return;
        }


        $controller = new $match["target"]["controller"];
        $method = $match["target"]["method"];

        call_user_func([$controller, $method], $match["params"], []);
    }
}
