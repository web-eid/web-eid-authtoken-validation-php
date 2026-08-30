<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

class LogWriter
{
    public function add()
    {
        $code = isset($_POST["code"]) ? $_POST["code"] : "";

        // Allow only certain type error codes
        if ($code != "ERR_WEBEID_USER_CANCELLED" || $code != "ERR_WEBEID_EXTENSION_UNAVAILABLE") {
            header("HTTP/1.0 405 Method Not Allowed");
            echo "Error code is not valid for logging";
        }

        $logger = new Logger();
        $logger->error(sprintf("Code: %s", $code));
        echo "success";
    }
}
