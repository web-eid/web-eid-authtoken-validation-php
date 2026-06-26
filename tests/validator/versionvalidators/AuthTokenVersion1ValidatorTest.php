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
use web_eid\web_eid_authtoken_validation_php\authtoken\UnverifiedSigningCertificate;
use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenException;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateValidatorBatch;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenSignatureValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidationConfiguration;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;

final class AuthTokenVersion1ValidatorTest extends TestCase
{
    private AuthTokenVersion1Validator $validator;

    protected function setUp(): void
    {
        $trustedCACertificates = CertificateValidator::buildTrustFromCertificates([]);
        $this->validator = new AuthTokenVersion1Validator(
            $this->createMock(SubjectCertificateValidatorBatch::class),
            $trustedCACertificates,
            $this->createMock(AuthTokenSignatureValidator::class),
            new AuthTokenValidationConfiguration(),
            $this->createMock(OcspClient::class),
            $this->createMock(OcspServiceProvider::class)
        );
    }

    /**
     * @dataProvider validFormats
     */
    public function testSupportsV1Formats(string $format): void
    {
        $this->assertTrue($this->validator->supports($format));
    }

    public static function validFormats(): array
    {
        return [
            ['web-eid:1'],
            ['web-eid:1.0'],
            ['web-eid:1.1'],
            ['web-eid:1.10'],
            ['web-eid:1.999'],
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
            ['web-eid'],
            ['web-eid:1.'],
            ['web-eid:1.0TEST'],
            ['web-eid:1.1.0'],
            ['web-eid:0.9'],
            ['web-eid:2'],
            ['webauthn:1'],
        ];
    }

    /**
     * @throws AuthTokenException
     */
    public function testUnverifiedSigningCertificatesPresentForV1Fails(): void
    {
        $token = $this->createMock(WebEidAuthToken::class);

        $token->method('getFormat')->willReturn('web-eid:1');
        $token->method('getUnverifiedSigningCertificates')->willReturn([
            $this->createMock(UnverifiedSigningCertificate::class)
        ]);

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage(
            "'unverifiedSigningCertificates' field is not allowed for format 'web-eid:1'"
        );

        $this->validator->validate($token, 'nonce');
    }

    /**
     * @throws AuthTokenException
     */
    public function testMissingUnverifiedCertificateFails(): void
    {
        $token = $this->createMock(WebEidAuthToken::class);

        $token->method('getUnverifiedCertificate')->willReturn(null);
        $token->method('getFormat')->willReturn('web-eid:1');

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'unverifiedCertificate' field is missing");

        $this->validator->validate($token, 'nonce');
    }
}
