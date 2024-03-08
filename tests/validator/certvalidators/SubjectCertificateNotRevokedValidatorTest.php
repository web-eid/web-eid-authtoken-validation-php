<?php

/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use phpseclib3\File\X509;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use web_eid\ocsp_php\OcspResponse;
use web_eid\ocsp_php\util\AsnUtil;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;
use web_eid\web_eid_authtoken_validation_php\testutil\Logger;
use web_eid\web_eid_authtoken_validation_php\testutil\OcspServiceMaker;
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClientImpl;

class SubjectCertificateNotRevokedValidatorTest extends TestCase
{
    private static OcspClient $ocspClient;
    private SubjectCertificateTrustedValidator $trustedValidator;
    private X509 $estEid2018Cert;

    public static function setUpBeforeClass(): void
    {
        self::$ocspClient = OcspClientImpl::build(5);
    }

    protected function setUp(): void
    {
        AsnUtil::loadOIDs();
        $this->trustedValidator = new SubjectCertificateTrustedValidator(new TrustedCertificates([]), new Logger());
        self::setSubjectCertificateIssuerCertificate($this->trustedValidator);
        $this->estEid2018Cert = Certificates::getJaakKristjanEsteid2018Cert();
    }

    public function testWhenValidAiaOcspResponderConfigurationThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingClient(self::$ocspClient);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenValidDesignatedOcspResponderConfigurationThenSucceeds(): void
    {
        $this->markTestSkipped("As new designated test OCSP responder certificates are issued more frequently now, it is no longer feasible to keep the certificates up to date");
        $this->expectNotToPerformAssertions();

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider();
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, self::$ocspClient, $ocspServiceProvider);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenValidOcspNonceDisabledConfigurationThenSucceeds(): void
    {
        $this->markTestSkipped("As new designated test OCSP responder certificates are issued more frequently now, it is no longer feasible to keep the certificates up to date");
        $this->expectNotToPerformAssertions();

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(false);
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, self::$ocspClient, $ocspServiceProvider);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspUrlIsInvalidThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: Could not resolve host: invalid.invalid");

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(true, "http://invalid.invalid");
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, self::$ocspClient, $ocspServiceProvider);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspRequestFailsThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: The requested URL returned error: 404");

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(true, "https://web-eid-test.free.beeceptor.com");
        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, self::$ocspClient, $ocspServiceProvider);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspRequestHasInvalidBodyThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: Exception: Could not decode OCSP response");
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse("invalid");
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseIsNotSuccessfulThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: OCSP response status: internalError");

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            pack("c*", ...self::buildOcspResponseBodyWithInternalErrorStatus())
        );
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHasInvalidCertificateIdThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: OCSP responded with certificate ID that differs from the requested ID");

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            pack("c*", ...self::buildOcspResponseBodyWithInvalidCertificateId())
        );
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHasInvalidSignatureThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: OCSP response signature is invalid");

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            pack("c*", ...self::buildOcspResponseBodyWithInvalidSignature())
        );
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHasInvalidResponderCertThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: Exception: Unable to decode BER");
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            pack("c*", ...self::buildOcspResponseBodyWithInvalidResponderCert())
        );
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHasInvalidTagThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: Exception: Could not decode OCSP response");
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            pack("c*", ...self::buildOcspResponseBodyWithInvalidTag())
        );
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseHas2CertResponsesThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: OCSP response must contain one response, received 2 responses instead");
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            pack("c*", ...self::getOcspResponseBytesFromResources("ocsp_response_with_2_responses.der"))
        );
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseRevokedThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: Exception: User certificate has been revoked");
        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            pack("c*", ...self::getOcspResponseBytesFromResources("ocsp_response_revoked.der"))
        );
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseUnknownThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: Exception: User certificate has been revoked: Unknown status");

        $ocspServiceProvider = OcspServiceMaker::getDesignatedOcspServiceProvider(true, "https://web-eid-test.free.beeceptor.com");
        $response = pack("c*", ...self::getOcspResponseBytesFromResources("ocsp_response_unknown.der"));

        $client = new class($response) implements OcspClient
        {
            private $response;

            public function __construct($response)
            {
                $this->response = $response;
            }

            public function request($url, $request): OcspResponse
            {
                return new OcspResponse($this->response);
            }
        };

        $validator = new SubjectCertificateNotRevokedValidator($this->trustedValidator, $client, $ocspServiceProvider);
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenOcspResponseCaNotTrustedThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: Exception: Certificate C=EE, O=AS Sertifitseerimiskeskus, OU=OCSP, CN=TEST of SK OCSP RESPONDER 2020/emailAddress=pki@sk.ee is not trusted");

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            pack("c*", ...self::getOcspResponseBytesFromResources("ocsp_response_unknown.der"))
        );
        $validator->validate($this->estEid2018Cert);
    }

    public function testWhenNonceDiffersThenThrows(): void
    {
        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: Exception: User certificate revocation check has failed: OCSP request and response nonces differ, possible replay attack");

        $validator = self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse(
            pack("c*", ...self::getOcspResponseBytesFromResources())
        );
        $validator->validate($this->estEid2018Cert);
    }

    private function getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingResponse($response): SubjectCertificateNotRevokedValidator
    {
        $client = new class($response) implements OcspClient
        {
            private $response;

            public function __construct($response)
            {
                $this->response = $response;
            }

            public function request($url, $request): OcspResponse
            {
                return new OcspResponse($this->response);
            }
        };

        return self::getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingClient($client);
    }

    // Either write the bytes of a real OCSP response to a file or use Python and asn1crypto.ocsp
    // to create a mock response, see OCSPBuilder in https://github.com/wbond/ocspbuilder/blob/master/ocspbuilder/__init__.py
    // and https://gist.github.com/mrts/bb0dcf93a2b9d2458eab1f9642ee97b2.
    private static function getOcspResponseBytesFromResources(string $resource = 'ocsp_response.der'): array
    {
        return array_values(unpack('c*', file_get_contents(__DIR__ . '/../../_resources/' . $resource)));
    }

    private static function buildOcspResponseBodyWithInternalErrorStatus(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $status_offset = 6;
        // 2 = internal error
        $ocspResponseBytes[$status_offset] = 2;
        return $ocspResponseBytes;
    }

    private static function buildOcspResponseBodyWithInvalidCertificateId(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $certificate_id_offset = 234;
        $ocspResponseBytes[$certificate_id_offset + 3] = 0x42;
        return $ocspResponseBytes;
    }

    private function buildOcspResponseBodyWithInvalidSignature(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $signature_offset = 348;
        $ocspResponseBytes[$signature_offset + 5 + 1] = 0x01;

        return $ocspResponseBytes;
    }

    private function buildOcspResponseBodyWithInvalidResponderCert(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $certificate_offset = 935;
        $ocspResponseBytes[$certificate_offset + 3] = 0x42;

        return $ocspResponseBytes;
    }

    private function buildOcspResponseBodyWithInvalidTag(): array
    {
        $ocspResponseBytes = self::getOcspResponseBytesFromResources();
        $tag_offset = 352;
        $ocspResponseBytes[$tag_offset] = 0x42;

        return $ocspResponseBytes;
    }

    private function getSubjectCertificateNotRevokedValidatorWithAiaOcspUsingClient(OcspClient $client): SubjectCertificateNotRevokedValidator
    {
        return new SubjectCertificateNotRevokedValidator($this->trustedValidator, $client, OcspServiceMaker::getAiaOcspServiceProvider());
    }

    private static function setSubjectCertificateIssuerCertificate(SubjectCertificateTrustedValidator $trustedValidator): void
    {
        $reflector = new ReflectionProperty(SubjectCertificateTrustedValidator::class, 'subjectCertificateIssuerCertificate');
        $reflector->setAccessible(true);
        $reflector->setValue($trustedValidator, Certificates::getTestEsteid2018CA());
    }
}
