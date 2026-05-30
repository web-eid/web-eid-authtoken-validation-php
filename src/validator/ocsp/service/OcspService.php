<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp\service;

use phpseclib3\File\X509;
use GuzzleHttp\Psr7\Uri;
use DateTime;

interface OcspService
{
    public function doesSupportNonce(): bool;

    public function getAccessLocation(): Uri;

    public function validateResponderCertificate(X509 $cert, DateTime $date): void;
}
