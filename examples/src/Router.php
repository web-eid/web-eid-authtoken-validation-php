<?php
/* App router */

class Router
{
    public function init()
    {

        $router = new AltoRouter();
        $router->setBasePath('');

        // Page routes
        $router->map('GET', '', ['controller' => 'Pages', 'method' => 'login']);
        $router->map('GET', '/', ['controller' => 'Pages', 'method' => 'login']);
        $router->map('GET', '/logout', ['controller' => 'Auth', 'method' => 'logout']);

        // Allow route onlu for authenticated users
        if (isset($_SESSION["auth-user"])) {
            $router->map('GET', '/welcome', ['controller' => 'Pages', 'method' => 'welcome']);
        }

        // Web eID routes
        $router->map('GET', '/nonce', ['controller' => 'Auth', 'method' => 'getNonce']);
        $router->map('POST', '/validate', ['controller' => 'Auth', 'method' => 'validate']);
        
        $match = $router->match();

        if (!$match) {
            // Redirect to login
            header("location:/");
            return;
        }


        $controller = new $match['target']['controller'];
        $method = $match['target']['method'];

        call_user_func([$controller, $method], $match['params'], []);        

    }
}