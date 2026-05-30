<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when the certificate's valid from date is in the future.
 */
class CertificateNotYetValidException extends AuthTokenException
{
    public function __construct(string $subject)
    {
        parent::__construct($subject . " certificate is not yet valid");
    }
}
