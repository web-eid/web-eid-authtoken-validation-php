<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp\exceptions;

/**
 * Thrown when OCSP response decoding fails
 */
class OcspResponseDecodeException extends OcspException
{
    public function __construct()
    {
        parent::__construct("Could not decode OCSP response");
    }
}
