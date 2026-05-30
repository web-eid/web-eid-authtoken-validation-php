<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

use Exception;
use Throwable;

/**
 * Base class for all authentication token validation exceptions.
 */
abstract class AuthTokenException extends Exception
{

    /**
     * @param string $message — [optional] The Exception message to throw
     * @param int $code — [optional] The Exception code
     * @param \Throwable|null $cause
     */
    public function __construct($message, ?Throwable $cause = null)
    {

        if (is_null($cause)) {
            parent::__construct($message);
        } else {
            parent::__construct($message, $cause->getCode(), $cause);
        }
    }
}
