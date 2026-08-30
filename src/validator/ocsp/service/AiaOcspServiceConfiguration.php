<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp\service;

use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use web_eid\web_eid_authtoken_validation_php\util\UriCollection;

class AiaOcspServiceConfiguration
{
    private UriCollection $nonceDisabledOcspUrls;
    private TrustedCertificates $trustedCACertificates;

    public function __construct(UriCollection $nonceDisabledOcspUrls, TrustedCertificates $trustedCACertificates)
    {
        $this->nonceDisabledOcspUrls = $nonceDisabledOcspUrls;
        $this->trustedCACertificates = $trustedCACertificates;
    }

    public function getNonceDisabledOcspUrls()
    {
        return $this->nonceDisabledOcspUrls;
    }

    public function getTrustedCACertificates()
    {
        return $this->trustedCACertificates;
    }
}
