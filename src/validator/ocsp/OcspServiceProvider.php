<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use InvalidArgumentException;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspService;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspServiceConfiguration;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\DesignatedOcspService;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\DesignatedOcspServiceConfiguration;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\OcspService;

class OcspServiceProvider
{
    private ?DesignatedOcspService $designatedOcspService;
    private AiaOcspServiceConfiguration $aiaOcspServiceConfiguration;

    public function __construct(?DesignatedOcspServiceConfiguration $designatedOcspServiceConfiguration, AiaOcspServiceConfiguration $aiaOcspServiceConfiguration)
    {
        $this->designatedOcspService = !is_null($designatedOcspServiceConfiguration) ? new DesignatedOcspService($designatedOcspServiceConfiguration) : null;
        $this->aiaOcspServiceConfiguration = $aiaOcspServiceConfiguration ?? throw new InvalidArgumentException("AIA Ocsp Service Configuration must not be null");

    }

    /**
     * A static factory method that returns either the designated or AIA OCSP service instance depending on whether
     * the designated OCSP service is configured and supports the issuer of the certificate.
     *
     * @param certificate subject certificate that is to be checked with OCSP
     * @return OcspService either the designated or AIA OCSP service instance
     */
    public function getService(X509 $certificate): OcspService
    {
        if (!is_null($this->designatedOcspService) && $this->designatedOcspService->supportsIssuerOf($certificate)) {
            return $this->designatedOcspService;
        }

        return new AiaOcspService($this->aiaOcspServiceConfiguration, $certificate);
    }
}
