<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp\exceptions;

/**
 * Thrown when OCSP response verification fails
 */
class OcspVerifyFailedException extends OcspException
{
    public function __construct(string $message)
    {
        parent::__construct($message);
    }
}
