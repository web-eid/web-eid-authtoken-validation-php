<?php

class Pages
{
    var $template;
    var $data = [];

    public function __construct()
    {
        $this->template = new Template();
    }

    public function login()
    {
        $this->data['content'] = $this->template->getHtml(__DIR__ . '/../tpl/login.phtml');
    }

    public function welcome()
    {
        if (!isset($_SESSION["auth-user"])) {
            // Redirect to login
            header("location:/");
            return;
        }

        $data = [];
        $data["auth_user"] = $_SESSION["auth-user"];
        $this->data['content'] = $this->template->getHtml(__DIR__ . '/../tpl/welcome.phtml', $data);
    }

    public function __destruct()
    {
        echo $this->template->getHtml(__DIR__ . '/../tpl/site.phtml', $this->data);
    }

}