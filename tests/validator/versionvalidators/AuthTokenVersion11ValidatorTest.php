<?php

/*
 * Copyright (c) 2025-2025 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\validator\versionvalidators;

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\authtoken\UnverifiedSigningCertificate;
use web_eid\web_eid_authtoken_validation_php\authtoken\SupportedSignatureAlgorithm;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenException;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenSignatureValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidationConfiguration;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateValidatorBatch;

final class AuthTokenVersion11ValidatorTest extends TestCase
{
    private AuthTokenVersion11Validator $validator;

    protected function setUp(): void
    {
        $trustedCACertificates = CertificateValidator::buildTrustFromCertificates([]);
        $this->validator = new AuthTokenVersion11Validator(
            $this->createMock(
                SubjectCertificateValidatorBatch::class
            ),
            $trustedCACertificates,
            $this->createMock(
                AuthTokenSignatureValidator::class
            ),
            new AuthTokenValidationConfiguration(),
            null,
            null
        );
    }

    /**
     * @dataProvider validFormats
     */
    public function testSupportsV11(string $format): void
    {
        $this->assertTrue($this->validator->supports($format));
    }

    public static function validFormats(): array
    {
        return [
            ['web-eid:1.1'],
            ['web-eid:1.1.0'],
            ['web-eid:1.10'],
        ];
    }

    /**
     * @dataProvider invalidFormats
     */
    public function testDoesNotSupportOtherFormats(?string $format): void
    {
        $this->assertFalse(
            $this->validator->supports($format)
        );
    }

    public static function invalidFormats(): array
    {
        return [
            [null],
            [''],
            ['web-eid:1'],
            ['web-eid:1.0'],
            ['web-eid:2'],
            ['webauthn:1.1'],
        ];
    }

    /**
     * @throws CertificateDecodingException
     * @throws AuthTokenException
     */
    public function testMissingSigningCertificatesFails(): void
    {
        $token = $this->createMock(WebEidAuthToken::class);

        $token->method('getFormat')->willReturn('web-eid:1.1');
        $token->method('getUnverifiedSigningCertificates')->willReturn([]);

        $spy = $this->getMockBuilder(AuthTokenVersion11Validator::class)
            ->setConstructorArgs([
                $this->createMock(SubjectCertificateValidatorBatch::class),
                CertificateValidator::buildTrustFromCertificates([]),
                $this->createMock(AuthTokenSignatureValidator::class),
                new AuthTokenValidationConfiguration(),
                null,
                null
            ])
            ->onlyMethods(['validateV1'])
            ->getMock();

        $spy->method('validateV1')->willReturn(new X509());

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage(
            "'unverifiedSigningCertificates' field is missing, null or empty for format 'web-eid:1.1'"
        );

        $spy->validate($token, 'nonce');
    }

    /**
     * @throws CertificateDecodingException
     * @throws AuthTokenException
     */
    public function testSigningCertificatesContainingNullEntryFails(): void
    {
        $token = $this->createMock(WebEidAuthToken::class);

        $token->method('getFormat')->willReturn('web-eid:1.1');
        $token->method('getUnverifiedSigningCertificates')->willReturn([null]);

        $spy = $this->getMockBuilder(AuthTokenVersion11Validator::class)
            ->setConstructorArgs([
                $this->createMock(SubjectCertificateValidatorBatch::class),
                CertificateValidator::buildTrustFromCertificates([]),
                $this->createMock(AuthTokenSignatureValidator::class),
                new AuthTokenValidationConfiguration(),
                null,
                null
            ])
            ->onlyMethods(['validateV1'])
            ->getMock();

        $spy->method('validateV1')->willReturn(new X509());

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage(
            "'unverifiedSigningCertificates' contains a null or empty entry for format 'web-eid:1.1'"
        );

        $spy->validate($token, 'nonce');
    }

    /**
     * @throws CertificateDecodingException
     * @throws AuthTokenException
     */
    public function testSigningCertificateValueMissingFails(): void
    {
        $token = $this->createMock(WebEidAuthToken::class);

        $certificate = new UnverifiedSigningCertificate();

        $token->method('getFormat')->willReturn('web-eid:1.1');
        $token->method('getUnverifiedSigningCertificates')->willReturn([$certificate]);

        $spy = $this->getMockBuilder(AuthTokenVersion11Validator::class)
            ->setConstructorArgs([
                $this->createMock(SubjectCertificateValidatorBatch::class),
                CertificateValidator::buildTrustFromCertificates([]),
                $this->createMock(AuthTokenSignatureValidator::class),
                new AuthTokenValidationConfiguration(),
                null,
                null
            ])
            ->onlyMethods(['validateV1'])
            ->getMock();

        $spy->method('validateV1')->willReturn(new X509());

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage(
            "'unverifiedSigningCertificates' contains a null or empty entry for format 'web-eid:1.1'"
        );

        $spy->validate($token, 'nonce');
    }

    /**
     * @throws CertificateDecodingException
     * @throws AuthTokenException
     */
    public function testMissingSupportedAlgorithmsFails(): void
    {
        $certPath = __DIR__ . '/../../_resources/ESTEID2018.cer';
        $der = file_get_contents($certPath);

        $this->assertIsString($der, "Certificate missing at: $certPath");

        $base64 = base64_encode($der);

        $certificate = UnverifiedSigningCertificate::fromArray([
            'certificate' => $base64,
            'supportedSignatureAlgorithms' => null,
        ]);

        $token = $this->createMock(WebEidAuthToken::class);
        $token->method('getFormat')->willReturn('web-eid:1.1');
        $token->method('getUnverifiedSigningCertificates')->willReturn([$certificate]);

        $spy = $this->getMockBuilder(AuthTokenVersion11Validator::class)
            ->setConstructorArgs([
                $this->createMock(SubjectCertificateValidatorBatch::class),
                CertificateValidator::buildTrustFromCertificates([]),
                $this->createMock(AuthTokenSignatureValidator::class),
                new AuthTokenValidationConfiguration(),
                null,
                null
            ])
            ->onlyMethods(['validateV1'])
            ->getMock();

        $spy->method('validateV1')->willReturn(new X509());

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'supportedSignatureAlgorithms' field is missing");

        $spy->validate($token, 'nonce');
    }
}
