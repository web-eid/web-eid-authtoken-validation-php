<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

/* App router */

class Router
{
    private $config;

    public function __construct($config) {
        $this->config = $config;
    }

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


        $controller = new $match["target"]["controller"]($this->config);
        $method = $match["target"]["method"];

        call_user_func([$controller, $method], $match["params"], []);
    }
}
