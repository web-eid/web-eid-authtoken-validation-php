<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use DateTime;
use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;
use web_eid\web_eid_authtoken_validation_php\testutil\OcspServiceMaker;
use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;

class OcspServiceProviderTest extends TestCase
{
    public function testWhenDesignatedOcspServiceConfigurationProvidedThenCreatesDesignatedOcspService(): void
    {
        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider();
        $service = $ocspServiceProvider->getService(Certificates::getJaakKristjanEsteid2018Cert());

        $this->assertEquals($service->getAccessLocation(), new Uri("http://demo.sk.ee/ocsp"));
        $this->assertTrue($service->doesSupportNonce());

        $service->validateResponderCertificate(Certificates::getTestSkOcspResponder2020(), new DateTime("Thursday, August 26, 2021 5:46:40 PM"));

        $this->expectException(OCSPCertificateException::class);
        $this->expectExceptionMessage("Responder certificate from the OCSP response is not equal to the configured designated OCSP responder certificate");

        $service->validateResponderCertificate(Certificates::getTestEsteid2018CA(), new DateTime("Thursday, August 26, 2021 5:46:40 PM"));
    }

    public function testWhenAiaOcspServiceConfigurationProvidedThenCreatesAiaOcspService(): void
    {
        // In PHP validation is different
        // we need to use TEST_of_EE-GovCA2018.pem.crt (getAiaOcspServiceConfiguration()) certificate for validation

        $ocspServiceProvider = OcspServiceMaker::getAiaOcspServiceProvider();

        $service2018 = $ocspServiceProvider->getService(Certificates::getJaakKristjanEsteid2018Cert());

        $this->assertEquals($service2018->getAccessLocation()->jsonSerialize(), (new Uri("http://aia.demo.sk.ee/esteid2018"))->jsonSerialize());
        $this->assertTrue($service2018->doesSupportNonce());

        $service2018->validateResponderCertificate(Certificates::getTestEsteid2018CA(), new DateTime('Thursday, August 26, 2021 5:46:40 PM'));

        // Responder certificate issuer is not in trusted certificates
        $service2015 = $ocspServiceProvider->getService(Certificates::getMariLiisEsteid2015Cert());
        $this->assertEquals($service2015->getAccessLocation()->jsonSerialize(), (new Uri("http://aia.demo.sk.ee/esteid2015"))->jsonSerialize());
        $this->assertFalse($service2015->doesSupportNonce());

        $this->expectException(CertificateNotTrustedException::class);
        $this->expectExceptionMessage("Certificate C=EE, O=AS Sertifitseerimiskeskus/organizationIdentifier=NTREE-10747013, CN=TEST of ESTEID-SK 2015 is not trusted");
        $service2015->validateResponderCertificate(Certificates::getTestEsteid2015CA(), new DateTime("Thursday, August 26, 2021 5:46:40 PM"));
    }

    public function testWhenAiaOcspServiceConfigurationDoesNotHaveResponderCertTrustedCaThenThrows(): void
    {
        $ocspServiceProvider = OcspServiceMaker::getAiaOcspServiceProvider();
        $service2018 = $ocspServiceProvider->getService(Certificates::getJaakKristjanEsteid2018Cert());

        $wrongResponderCert = Certificates::getMariliisEsteid2015Cert();
        $this->expectException(OCSPCertificateException::class);

        $service2018->validateResponderCertificate($wrongResponderCert, new DateTime("Thursday, August 26, 2021 5:46:40 PM"));
    }
}
