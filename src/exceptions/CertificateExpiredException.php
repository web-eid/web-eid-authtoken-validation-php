<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when the certificate's valid until date is in the past.
 */
class CertificateExpiredException extends AuthTokenException
{
    public function __construct(string $subject)
    {
        parent::__construct($subject . " certificate has expired");
    }
}
