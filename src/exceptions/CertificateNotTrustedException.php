<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

use phpseclib3\File\X509;
use Throwable;

/**
 * Thrown when the given certificate is not signed by a trusted CA.
 */
class CertificateNotTrustedException extends AuthTokenException
{

    public function __construct(X509 $certificate, ?Throwable $cause = null)
    {
        parent::__construct("Certificate " . $certificate->getSubjectDN(X509::DN_STRING) . " is not trusted", $cause);
    }
}
