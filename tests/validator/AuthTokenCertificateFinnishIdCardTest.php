<?php

/*
 * Copyright (c) 2022-2025 Estonian Information System Authority
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


namespace web_eid\web_eid_authtoken_validation_php\validator;

use DateTime;
use web_eid\web_eid_authtoken_validation_php\testutil\AbstractTestWithValidator;
use web_eid\web_eid_authtoken_validation_php\testutil\AuthTokenValidators;
use web_eid\web_eid_authtoken_validation_php\testutil\Dates;

class AuthTokenCertificateFinnishIdCardTest extends AbstractTestWithValidator
{

    private const FINNISH_TEST_ID_CARD_BACKMAN_JUHANI_AUTH_TOKEN =
        '{' .
        '  "action": "web-eid:authenticate-success",' .
        '  "algorithm": "ES384",' .
        '  "appVersion": "https://web-eid.eu/web-eid-app/releases/2.7.0+965",' .
        '  "format": "web-eid:1.0",' .
        '  "signature": "dUzVVAvN4dLFSKo0De4WQsDMiXpoQVjT8km6RLePeRyhlsA7swaq7XLfGOO1Qw4o5DrWAKBOlElwpJO9GgO6nPhDsco4SVKHSdSKbJMvg0E8qrCo3dUbdT/Y5UhKFPNl",' .
        '  "unverifiedCertificate": "MIIEOjCCA7+gAwIBAgIEBhwJHTAMBggqhkjOPQQDAwUAMHgxCzAJBgNVBAYTAkZJMSkwJwYDVQQKDCBEaWdpLSBqYSB2YWVzdG90aWV0b3ZpcmFzdG8gVEVTVDEYMBYGA1UECwwPVGVzdGl2YXJtZW50ZWV0MSQwIgYDVQQDDBtEVlYgVEVTVCBDZXJ0aWZpY2F0ZXMgLSBHNUUwHhcNMjMwMTI1MjIwMDAwWhcNMjgwMTIzMjE1OTU5WjB5MQswCQYDVQQGEwJGSTESMBAGA1UEBRMJOTk5MDIwMDE2MQ8wDQYDVQQqDAZKVUhBTkkxGTAXBgNVBAQMEFNQRUNJTUVOLUJBQ0tNQU4xKjAoBgNVBAMMIVNQRUNJTUVOLUJBQ0tNQU4gSlVIQU5JIDk5OTAyMDAxNjB2MBAGByqGSM49AgEGBSuBBAAiA2IABKq3yVI9NYmZwV2Matvk6yXFLLYn087ldhvl1AfCRoV8mTGhmL+y/R4DzaTeTrS9epEUcR9x2697h6DLBUkiOlAcI3nN92RJgNlBOCdvBdNcYgx57njSJHde4Rsm5gmLLqOCAhUwggIRMB8GA1UdIwQYMBaAFBKet+Iox/OUaou9Tcb0wjaXUkIIMB0GA1UdDgQWBBS8olmlfP/C700H4k/wLPrKX513QzAOBgNVHQ8BAf8EBAMCA4gwgc0GA1UdIASBxTCBwjCBvwYKKoF2hAVjCoJgATCBsDAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5maW5laWQuZmkvY3BzOTkvMIGEBggrBgEFBQcCAjB4GnZWYXJtZW5uZXBvbGl0aWlra2Egb24gc2FhdGF2aWxsYSAtIENlcnRpZmlrYXRwb2xpY3kgZmlubnMgLSBDZXJ0aWZpY2F0ZSBwb2xpY3kgaXMgYXZhaWxhYmxlIGh0dHA6Ly93d3cuZmluZWlkLmZpL2Nwczk5MDAGA1UdEQQpMCeBJVMxSnVoYW5pMDQ5LlNQRUNJTUVOLUJhY2ttYW5AdGVzdGkuZmkwDwYDVR0TAQH/BAUwAwEBADA4BgNVHR8EMTAvMC2gK6AphidodHRwOi8vcHJveHkuZmluZWlkLmZpL2NybC9kdnZ0cDVlYy5jcmwwcgYIKwYBBQUHAQEEZjBkMDIGCCsGAQUFBzAChiZodHRwOi8vcHJveHkuZmluZWlkLmZpL2NhL2R2dnRwNWVjLmNydDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3B0ZXN0LmZpbmVpZC5maS9kdnZ0cDVlYzAMBggqhkjOPQQDAwUAA2cAMGQCMClSh2MQZVYZyKfgmntQxuVUtQvIIqs8aOdsKpla4wt/IU6hMbGEAfIv4AzLXLsS5QIwUcjlY8BCj4+x84ihAqqHNIle6kyKek/Tj994SjQBmUadtyUSDvg8O5MppKvgJCNV"' .
        '}';

    private const FINNISH_TEST_ID_CARD_BABAFO_VELI_AUTH_TOKEN =
        '{' .
        '  "action": "web-eid:authenticate-success",' .
        '  "algorithm": "PS256",' .
        '  "appVersion": "https://web-eid.eu/web-eid-app/releases/2.7.0+965",' .
        '  "format": "web-eid:1.0",' .
        '  "signature": "TFJ+l/NyDIMzoRyJxXprA88kBZXTvQ1gu2vUWhf4sz468acq46WWllIVs9/nIwBRMt3cPnDwKT21EkgIBc/bhBO+7SlWcRAov0N9Nja0pebJAfYKyY0VONN9T4/LRnCg3NVFZequuk+6roV1vVPhySmOz29w/HM5F5tENbxkgn5uw3q7H44qUVE/s01vhmiCHpz98HGm01jX4p6Pm1IxQ5lcx+2wSYvm0t1G973pz+SXmJBE0rGOS8v+bmP15mIiIyGYeUFIvgw9cWsLhgyhYZwymm+Isfa/wAKbtmxT1bI2a7xIR+XDrG4xrwqOETaYUzshOfgvD5JViY+GLianbA==",' .
        '  "unverifiedCertificate": "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"' .
        '}';

    
    protected function setUp(): void
    {
        parent::setUp();
        // Ensure that the certificates do not expire.
        $this->mockDate("2024-12-24");
    }

    protected function tearDown(): void
    {
        Dates::resetMockedCertificateValidatorDate();
    }

    public function testWhenIdCardSignatureCertificateWithG5ERootCertificateIsValidatedThenValidationSucceeds(): void
    {
        $this->expectNotToPerformAssertions();
        $validator = AuthTokenValidators::getAuthTokenValidatorForFinnishIdCard();
        $token = $validator->parse(self::FINNISH_TEST_ID_CARD_BACKMAN_JUHANI_AUTH_TOKEN);

        $validator->validate($token, 'x9qZDRO/ao2zprt3Z0bkW4CvvE/gALFtUIf3tcC0XxY=');
    }

    public function testWhenIdCardSignatureCertificateWithG4RootCertificateIsValidatedThenValidationSucceeds(): void
    {
        $this->expectNotToPerformAssertions();
        $validator = AuthTokenValidators::getAuthTokenValidatorForFinnishIdCard();
        $token = $validator->parse(self::FINNISH_TEST_ID_CARD_BABAFO_VELI_AUTH_TOKEN);

        $validator->validate($token, 'ZqlDATkQRqh7LkqEbspBc2qDjot29oiNLlITdLgiVIo=');
    }

    private function mockDate(string $date)
    {
        Dates::setMockedCertificateValidatorDate(new DateTime($date));
    }

}
