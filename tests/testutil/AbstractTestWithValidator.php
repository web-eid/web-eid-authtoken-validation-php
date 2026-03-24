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

namespace web_eid\web_eid_authtoken_validation_php\testutil;

use PHPUnit\Framework\TestCase;
use Throwable;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidator;
use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use RuntimeException;

abstract class AbstractTestWithValidator extends TestCase
{

    /*  notBefore Time UTCTime 2021-07-22 12:43:08 UTC
     *  notAfter Time UTCTime 2026-07-09 21:59:59 UTC
     */
    public const VALID_AUTH_TOKEN = '{"algorithm":"ES384",' .
        '"unverifiedCertificate":"MIIEBDCCA2WgAwIBAgIQY5OGshxoPMFg+Wfc0gFEaTAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTIxMDcyMjEyNDMwOFoXDTI2MDcwOTIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQmwEKsJTjaMHSaZj19hb9EJaJlwbKc5VFzmlGMFSJVk4dDy+eUxa5KOA7tWXqzcmhh5SYdv+MxcaQKlKWLMa36pfgv20FpEDb03GCtLqjLTRZ7649PugAQ5EmAqIic29CjggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFPlp/ceABC52itoqppEmbf71TJz6MGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgDCAgybz0u3W+tGI+AX+PiI5CrE9ptEHO5eezR1Jo4j7iGaO0i39xTGUB+NSC7P6AQbyE/ywqJjA1a62jTLcS9GHAJCARxN4NO4eVdWU3zVohCXm8WN3DWA7XUcn9TZiLGQ29P4xfQZOXJi/z4PNRRsR4plvSNB3dfyBvZn31HhC7my8woi",' .
        '"appVersion":"https://web-eid.eu/web-eid-app/releases/2.5.0+0",' .
        '"signature":"0Ov7ME6pTY1K2GXMj8Wxov/o2fGIMEds8OMY5dKdkB0nrqQX7fG1E5mnsbvyHpMDecMUH6Yg+p1HXdgB/lLqOcFZjt/OVXPjAAApC5d1YgRYATDcxsR1zqQwiNcHdmWn",' .
        '"format":"web-eid:1.0"}';

    public const VALID_V11_AUTH_TOKEN = '{"algorithm":"ES384",' .
        '"unverifiedCertificate":"MIIEBDCCA2WgAwIBAgIQY5OGshxoPMFg+Wfc0gFEaTAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTIxMDcyMjEyNDMwOFoXDTI2MDcwOTIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQmwEKsJTjaMHSaZj19hb9EJaJlwbKc5VFzmlGMFSJVk4dDy+eUxa5KOA7tWXqzcmhh5SYdv+MxcaQKlKWLMa36pfgv20FpEDb03GCtLqjLTRZ7649PugAQ5EmAqIic29CjggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFPlp/ceABC52itoqppEmbf71TJz6MGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgDCAgybz0u3W+tGI+AX+PiI5CrE9ptEHO5eezR1Jo4j7iGaO0i39xTGUB+NSC7P6AQbyE/ywqJjA1a62jTLcS9GHAJCARxN4NO4eVdWU3zVohCXm8WN3DWA7XUcn9TZiLGQ29P4xfQZOXJi/z4PNRRsR4plvSNB3dfyBvZn31HhC7my8woi",' .
        '"unverifiedSigningCertificates":[{' .
            '"certificate":"MIID6zCCA02gAwIBAgIQT7j6zk6pmVRcyspLo5SqejAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDUzMVoXDTI5MDUwMjEwNDUzMVowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASkwENR8GmCpEs6OshDWDfIiKvGuyNMOD2rjIQW321AnZD3oIsqD0svBMNEJJj9Dlvq/47TYDObIa12KAU5IuOBfJs2lrFdSXZjaM+a5TWT3O2JTM36YDH2GcMe/eisepejggGrMIIBpzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGQDBIBgNVHSAEQTA/MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAJBgcEAIvsQAECMB0GA1UdDgQWBBTVX3s48Spy/Es2TcXgkRvwUn2YcjCBigYIKwYBBQUHAQMEfjB8MAgGBgQAjkYBATAIBgYEAI5GAQQwEwYGBACORgEGMAkGBwQAjkYBBgEwUQYGBACORgEFMEcwRRY/aHR0cHM6Ly9zay5lZS9lbi9yZXBvc2l0b3J5L2NvbmRpdGlvbnMtZm9yLXVzZS1vZi1jZXJ0aWZpY2F0ZXMvEwJFTjAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBiwAwgYcCQgGBr+Jbo1GeqgWdIwgMo7SA29AP38JxNm2HWq2Qb+kIHpusAK574Co1K5D4+Mk7/ITTuXQaET5WphHoN7tdAciTaQJBAn0zBigYyVPYSTO68HM6hmlwTwi/KlJDdXW/2NsMjSqofFFJXpGvpxk2CTqSRCjcavxLPnkasTbNROYSJcmM8Xc=",' .
            '"supportedSignatureAlgorithms":[{"cryptoAlgorithm":"RSA","hashFunction":"SHA-256","paddingScheme":"PKCS1.5"}]' .
        '}],' .
        '"appVersion":"https://web-eid.eu/web-eid-mobile-app/releases/v1.0.0",' .
        '"signature":"0Ov7ME6pTY1K2GXMj8Wxov/o2fGIMEds8OMY5dKdkB0nrqQX7fG1E5mnsbvyHpMDecMUH6Yg+p1HXdgB/lLqOcFZjt/OVXPjAAApC5d1YgRYATDcxsR1zqQwiNcHdmWn",' .
        '"format":"web-eid:1.1"}';

    public const VALID_CHALLENGE_NONCE = '12345678123456781234567812345678912356789123';

    protected AuthTokenValidator $validator;
    protected WebEidAuthToken $validAuthToken;

    protected function setUp(): void
    {
        try {
            $this->validator = AuthTokenValidators::getAuthTokenValidator();
            $this->validAuthToken = $this->validator->parse(self::VALID_AUTH_TOKEN);
        } catch (Throwable $e) {
            throw new RuntimeException('AbstractTestWithValidator setup failed', -1, $e);
        }
    }

    protected function replaceTokenField(string $token, string $field, $value): WebEidAuthToken
    {
        $tokenToArray = json_decode($token, true);
        $tokenToArray[$field] = $value;
        $result = json_encode($tokenToArray);
        if (!$result) {
            return $this->validAuthToken;
        }
        return $this->validator->parse($result);
    }

    protected function removeTokenField(string $token, string $field): WebEidAuthToken
    {
        $tokenToArray = json_decode($token, true);
        unset($tokenToArray[$field]);
        $result = json_encode($tokenToArray);
        if (!$result) {
            return $this->validAuthToken;
        }
        return $this->validator->parse($result);
    }

    protected function replaceJsonSnippet(string $json, string $search, string $replace): string
    {
        $updated = str_replace($search, $replace, $json);

        if ($updated === $json) {
            throw new \RuntimeException("replaceJsonSnippet(): No replacement occurred! Search string not found.");
        }

        if (json_decode($updated) === null) {
            throw new \RuntimeException("Generated JSON is invalid after replacement. JSON: $updated");
        }

        return $updated;
    }
}
