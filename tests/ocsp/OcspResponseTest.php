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

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp;

use DateTime;
use phpseclib3\File\ASN1;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use UnexpectedValueException;
use web_eid\web_eid_authtoken_validation_php\ocsp\exceptions\OcspCertificateException;
use web_eid\web_eid_authtoken_validation_php\ocsp\exceptions\OcspResponseDecodeException;
use web_eid\web_eid_authtoken_validation_php\ocsp\exceptions\OcspVerifyFailedException;
use web_eid\web_eid_authtoken_validation_php\util\AsnUtil;

class OcspResponseTest extends TestCase
{

    protected function setUp(): void
    {
        AsnUtil::loadOIDs();
    }

    // Either write the bytes of a real OCSP response to a file or use Python and asn1crypto.ocsp
    // to create a mock response, see OCSPBuilder in https://github.com/wbond/ocspbuilder/blob/master/ocspbuilder/__init__.py
    // and https://gist.github.com/mrts/bb0dcf93a2b9d2458eab1f9642ee97b2.    
    private static function getOcspResponseBytesFromResources(string $resource = 'ocsp_response.der'): string
    {
        return file_get_contents(__DIR__ . '/../_resources/' . $resource);
    }

    public function testWhenResponseDecodeFailsThenThrows(): void
    {
        $this->expectException(OcspResponseDecodeException::class);
        $this->expectExceptionMessage("Could not decode OCSP response");
        new OcspResponse("1");
    }

    public function testWhenCertificateNotRevoked(): void
    {
        $response = new OcspResponse(self::getOcspResponseBytesFromResources());
        $basicResponse = $response->getBasicResponse();

        $mockCertificateID = $basicResponse->getResponses()[0]['certID'];
        $mockCertificateID['hashAlgorithm']['algorithm'] = ASN1::getOID('id-sha1');

        $response->validateCertificateId($mockCertificateID);
        $response->validateSignature();

        $this->assertFalse($response->isRevoked());
        $this->assertEquals("successful", $response->getStatus());
        $this->assertEquals("2021-09-17 18:25:24", $basicResponse->getProducedAt()->format("Y-m-d H:i:s"));
        $this->assertEquals("2021-09-17 18:25:24", $basicResponse->getThisUpdate()->format("Y-m-d H:i:s"));
        $this->assertNull($basicResponse->getNextUpdate());
        $this->assertEquals([71, 255, 175, 201, 24, 17, 119, 14], array_values(unpack('C*', $basicResponse->getNonceExtension())));
    }

    public function testWhenCertificateIsRevoked(): void
    {
        $response = new OcspResponse(self::getOcspResponseBytesFromResources("ocsp_response_revoked.der"));
        $this->assertTrue($response->isRevoked());
        $this->assertEquals("unspecified", $response->getRevokeReason());
    }

    public function testWhenCertificateRevokeStatusIsUnknown(): void
    {
        $response = new OcspResponse(self::getOcspResponseBytesFromResources("ocsp_response_unknown.der"));
        $this->assertNull($response->isRevoked());
    }

    public function testWhenTwoResponsesThenThrows(): void
    {
        $response = new OcspResponse(self::getOcspResponseBytesFromResources("ocsp_response_with_2_responses.der"));
        $basicResponse = $response->getBasicResponse();

        $mockCertificateID = $basicResponse->getResponses()[0]['certID'];
        $mockCertificateID['hashAlgorithm']['algorithm'] = ASN1::getOID('id-sha1');

        $this->expectException(OcspVerifyFailedException::class);
        $this->expectExceptionMessage("OCSP response must contain one response, received 2 responses instead");

        $response->isRevoked();
    }

    public function testWhenCertificateIdsDoNotMatchThenThrows(): void
    {
        $response = new OcspResponse(self::getOcspResponseBytesFromResources());
        $basicResponse = $response->getBasicResponse();

        $mockCertificateID = $basicResponse->getResponses()[0]['certID'];
        $mockCertificateID['issuerNameHash'] = "1234";
        $mockCertificateID['hashAlgorithm']['algorithm'] = ASN1::getOID('id-sha1');

        $this->expectException(OcspVerifyFailedException::class);
        $this->expectExceptionMessage("OCSP responded with certificate ID that differs from the requested ID");

        $response->validateCertificateId($mockCertificateID);
    }

    public function testWhenResponseTypeNotBasicResponseThrows(): void
    {

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('responseType is not "id-pkix-ocsp-basic" but is responseType');

        $response = new OcspResponse(self::getOcspResponseBytesFromResources());

        $reflection = new ReflectionClass(get_class($response));
        $property = $reflection->getProperty('ocspResponse');
        $property->setAccessible(true);
        $mockResponse = $property->getValue($response);
        $mockResponse['responseBytes']['responseType'] = "responseType";
        $property->setValue($response, $mockResponse);

        $response->getBasicResponse();
    }

    public function testWhenMissingResponseThrows(): void
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Could not decode OcspResponse->responseBytes->response');

        $response = new OcspResponse(self::getOcspResponseBytesFromResources());

        $reflection = new ReflectionClass(get_class($response));
        $property = $reflection->getProperty('ocspResponse');
        $property->setAccessible(true);
        $mockResponse = $property->getValue($response);
        $mockResponse['responseBytes']['response'] = null;
        $property->setValue($response, $mockResponse);

        $response->getBasicResponse();
    }

    public function testWhenNoCertificatesInResponseThrows(): void
    {
        $this->expectException(OcspVerifyFailedException::class);
        $this->expectExceptionMessage('OCSP response must contain the responder certificate, but none was provided');

        $response = new OcspResponse(self::getOcspResponseBytesFromResources());

        $basicResponse = $response->getBasicResponse();
        $mockCertificateID = $basicResponse->getResponses()[0]['certID'];
        $mockCertificateID['hashAlgorithm']['algorithm'] = ASN1::getOID('id-sha1');

        $reflection = new ReflectionClass(get_class($response));
        $property = $reflection->getProperty('ocspResponse');
        $property->setAccessible(true);
        $mockResponse = $property->getValue($response);
        $mockResponse['responseBytes']['response']['certs'] = [];

        $property->setValue($response, $mockResponse);

        $response->isRevoked();
    }

    public function testWhenResponseSignatureIsNotValidThrows(): void
    {
        $this->expectException(OcspVerifyFailedException::class);
        $this->expectExceptionMessage('OCSP response signature is not valid');

        $response = new OcspResponse(self::getOcspResponseBytesFromResources());

        $basicResponse = $response->getBasicResponse();
        $mockCertificateID = $basicResponse->getResponses()[0]['certID'];
        $mockCertificateID['hashAlgorithm']['algorithm'] = ASN1::getOID('id-sha1');

        $reflection = new ReflectionClass(get_class($response));
        $property = $reflection->getProperty('ocspResponse');
        $property->setAccessible(true);
        $mockResponse = $property->getValue($response);
        $mockResponse['responseBytes']['response']['signature'] = "somesignature";

        $property->setValue($response, $mockResponse);

        $response->validateSignature();
    }

    public function testWhenSignatureAlgorithmIsSha3(): void
    {
        $response = new OcspResponse(self::getOcspResponseBytesFromResources());

        $reflection = new ReflectionClass(get_class($response));
        $property = $reflection->getProperty('ocspResponse');
        $property->setAccessible(true);
        $mockResponse = $property->getValue($response);
        $mockResponse['responseBytes']['response']['signatureAlgorithm']['algorithm'] = "NNNsha3-256NNN";
        $property->setValue($response, $mockResponse);

        $basicResponse = $response->getBasicResponse();

        $this->assertEquals("sha3-256", $basicResponse->getSignatureAlgorithm());
    }

    public function testWhenSignatureAlgorithmIsNotSupportedThenThrows(): void
    {

        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage('Signature algorithm somealgo not implemented');

        $response = new OcspResponse(self::getOcspResponseBytesFromResources());

        $reflection = new ReflectionClass(get_class($response));
        $property = $reflection->getProperty('ocspResponse');
        $property->setAccessible(true);
        $mockResponse = $property->getValue($response);
        $mockResponse['responseBytes']['response']['signatureAlgorithm']['algorithm'] = "someAlgo";
        $property->setValue($response, $mockResponse);

        $basicResponse = $response->getBasicResponse();
        $basicResponse->getSignatureAlgorithm();
    }

    public function testWhenNextUpdateInResponse(): void
    {

        $response = new OcspResponse(self::getOcspResponseBytesFromResources());

        $reflection = new ReflectionClass(get_class($response));
        $property = $reflection->getProperty('ocspResponse');
        $property->setAccessible(true);
        $mockResponse = $property->getValue($response);
        $mockResponse['responseBytes']['response']['tbsResponseData']['responses'][0]['nextUpdate'] = 'Fri, 17 Sep 2021 18:25:24 +0000';
        $property->setValue($response, $mockResponse);

        $basicResponse = $response->getBasicResponse();

        $this->assertEquals(new DateTime("Fri, 17 Sep 2021 18:25:24 +0000"), $basicResponse->getNextUpdate());
    }

    public function testWhenNonceExtensionDoesNotExistNullShouldReturned(): void
    {

        $response = new OcspResponse(self::getOcspResponseBytesFromResources());

        $reflection = new ReflectionClass(get_class($response));
        $property = $reflection->getProperty('ocspResponse');
        $property->setAccessible(true);
        $mockResponse = $property->getValue($response);
        $mockResponse['responseBytes']['response']['tbsResponseData']['responseExtensions'][0]['extnId'] = "id-pkix-ocsp-nonce1";
        $property->setValue($response, $mockResponse);

        $basicResponse = $response->getBasicResponse();

        $this->assertNull($basicResponse->getNonceExtension());
    }
}
