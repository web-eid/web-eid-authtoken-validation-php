<?php

/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
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
