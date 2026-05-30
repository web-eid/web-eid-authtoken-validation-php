<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

use Throwable;

/**
 * Thrown when the there was some error with certificate during OCSP process.
 */
class OCSPCertificateException extends AuthTokenException
{
    public function __construct(string $message, ?Throwable $exception = null)
    {
        parent::__construct($message, $exception);
    }
}
