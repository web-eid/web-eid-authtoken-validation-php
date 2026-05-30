<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

header('Content-type: text/html; charset=UTF-8');

session_start();

// Uncomment following line to define the custom log location (by default the server log is used)
//define("LOGFILE", dirname(__FILE__) . "/../log/web-eid-authtoken-validation-php.log");

require __DIR__ . '/../vendor/autoload.php';

$configArr = require_once __DIR__ . '/../src/app.conf.php';
$config = Config::fromArray($configArr)->overrideFromEnv();
$router = new Router($config);
$router->init();
