<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

use Throwable;

class AuthTokenParseException extends AuthTokenException
{
    public function __construct(string $message, ?Throwable $cause = null)
    {
        parent::__construct($message, $cause);
    }
}
