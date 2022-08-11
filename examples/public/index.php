<?php

header('Content-type: text/html; charset=UTF-8');

session_start();

// Define the log location
define("LOGFILE", dirname(__FILE__) . "/../log/web-eid-authtoken-validation-php.log");

require __DIR__ . '/../vendor/autoload.php';

$router = new Router();
$router->init();