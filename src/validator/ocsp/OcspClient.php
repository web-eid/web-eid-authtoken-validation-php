<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\ocsp\OcspResponse;

interface OcspClient
{
    public function request(Uri $url, string $requestBody): OcspResponse;
}
