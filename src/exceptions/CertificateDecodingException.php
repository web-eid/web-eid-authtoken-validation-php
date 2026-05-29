<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

class CertificateDecodingException extends AuthTokenException
{
    public function __construct(string $resource)
    {
        parent::__construct("Certificate decoding from Base64 or parsing failed for " . $resource);
    }
}
