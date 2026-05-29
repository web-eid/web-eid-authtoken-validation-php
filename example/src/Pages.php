<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

class Pages
{
    var $template;
    var $data = [];

    public function __construct()
    {
        $this->template = new Template();
    }

    private function _generateCsrfToken()
    {
        // Store token to session
        $_SESSION["csrf-token"] = bin2hex(random_bytes(32));
        return $_SESSION["csrf-token"];
    }

    public function login()
    {
        $this->data = [
            "content" => $this->template->getHtml(__DIR__ . '/../tpl/login.phtml')
        ];
    }

    public function welcome()
    {
        $data = ["auth_user" => $_SESSION["auth-user"]];
        $this->data = [
            "content" => $this->template->getHtml(__DIR__ . '/../tpl/welcome.phtml', $data)
        ];
    }

    public function __destruct()
    {
        $this->data["token"] = $this->_generateCsrfToken();;
        echo $this->template->getHtml(__DIR__ . '/../tpl/site.phtml', $this->data);
    }
}
