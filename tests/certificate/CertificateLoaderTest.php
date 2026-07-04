<?php

/*
 * Copyright (c) 2026 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\certificate;

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;

class CertificateLoaderTest extends TestCase
{
    public function testWhenCertificateListIsNullThenEmptyArrayIsReturned(): void
    {
        $this->assertSame(
            [],
            CertificateLoader::decodeCertificatesFromBase64(null, "unverifiedIntermediateCertificates")
        );
    }

    public function testWhenCertificateListIsEmptyThenEmptyArrayIsReturned(): void
    {
        $this->assertSame(
            [],
            CertificateLoader::decodeCertificatesFromBase64([], "unverifiedIntermediateCertificates")
        );
    }

    public function testWhenCertificateListContainsValidCertificatesThenTheyAreDecodedInOrder(): void
    {
        $certificates = CertificateLoader::decodeCertificatesFromBase64(
            [
                self::getCertificateInBase64("TEST_of_ESTEID2018.cer"),
                self::getCertificateInBase64("ESTEID2018.cer"),
            ],
            "unverifiedIntermediateCertificates"
        );

        $this->assertCount(2, $certificates);
        $this->assertSame(
            ["TEST of ESTEID2018"],
            $certificates[0]->getSubjectDNProp("id-at-commonName")
        );
        $this->assertSame(
            ["ESTEID2018"],
            $certificates[1]->getSubjectDNProp("id-at-commonName")
        );
    }

    public function testWhenCertificateListContainsNonBase64EntryThenDecodingFails(): void
    {
        $this->expectException(CertificateDecodingException::class);
        $this->expectExceptionMessage("'unverifiedIntermediateCertificates' decode failed");
        CertificateLoader::decodeCertificatesFromBase64(
            ["not-valid-base64!!!"],
            "unverifiedIntermediateCertificates"
        );
    }

    public function testWhenCertificateListContainsBase64ThatIsNotCertificateThenDecodingFails(): void
    {
        $this->expectException(CertificateDecodingException::class);
        $this->expectExceptionMessage("'unverifiedIntermediateCertificates' decode failed");
        CertificateLoader::decodeCertificatesFromBase64(
            [base64_encode("this is definitely not a DER-encoded certificate")],
            "unverifiedIntermediateCertificates"
        );
    }

    public function testWhenCertificateListContainsNullEntryThenParsingFails(): void
    {
        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'unverifiedIntermediateCertificates' field is missing, null or empty");
        CertificateLoader::decodeCertificatesFromBase64(
            [null],
            "unverifiedIntermediateCertificates"
        );
    }

    public function testWhenCertificateListContainsEmptyEntryThenParsingFails(): void
    {
        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'unverifiedIntermediateCertificates' field is missing, null or empty");
        CertificateLoader::decodeCertificatesFromBase64(
            [""],
            "unverifiedIntermediateCertificates"
        );
    }

    private static function getCertificateInBase64(string $resourceName): string
    {
        $der = file_get_contents(__DIR__ . "/../_resources/" . $resourceName);
        return base64_encode($der);
    }
}
