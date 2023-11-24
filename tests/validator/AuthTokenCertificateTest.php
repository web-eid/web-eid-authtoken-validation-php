<?php

/*
 * Copyright (c) 2022-2023 Estonian Information System Authority
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

use web_eid\web_eid_authtoken_validation_php\testutil\AbstractTestWithValidator;
use web_eid\web_eid_authtoken_validation_php\testutil\Dates;
use web_eid\web_eid_authtoken_validation_php\testutil\AuthTokenValidators;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateMissingPurposeException;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateWrongPurposeException;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateDisallowedPolicyException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotYetValidException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
use DateTime;
use UnexpectedValueException;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;

class AuthTokenCertificateTest extends AbstractTestWithValidator
{

    private const AUTH_TOKEN = '{"algorithm":"ES384",' .
        '"unverifiedCertificate":"X5C",' .
        '"appVersion":"https://web-eid.eu/web-eid-app/releases/2.0.0+0",' .
        '"signature":"arx164xRiwhIQDINe0J+ZxJWZFOQTx0PBtOaWaxAe7gofEIHRIbV1w0sOCYBJnvmvMem9hU4nc2+iJx2x8poYck4Z6eI3GwtiksIec3XQ9ZIk1n/XchXnmPn3GYV+HzJ",' .
        '"format":"web-eid:1"}';

    private const MISSING_PURPOSE_CERT = 'MIICxjCCAa6gAwIBAgIJANTbd26vS6fmMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNVBAMTCndlYi1laWQuZXUwHhcNMjAwOTI0MTIyNDMzWhcNMzAwOTIyMTIyNDMzWjAVMRMwEQYDVQQDEwp3ZWItZWlkLmV1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAza5qBFu5fvs47rx3o9yzBVfIxHjMotID8ppkwWVen/uFxlqsRVi+XnWkggW+K8X45inAnBAVi1rIw7GQNdacSHglyvQfwM64AallmD0+K+QgbqxcO9fvRvlAeISENBc2bGgqTIytPEON5ZmazzbOZjqY3M1QcPlPZOeUm6M9ZcZFhsxpiB4gwZUic9tnCz9eujd6k6DzNVfSRaJcpGA5hJ9aKH4vXS3x7anewna+USEXkRb4Il5zSlZR0i1yrVA1YNOxCG/+GgWvXfvXwdQ0z9BpGwNEyc0mRDNx+umaTukz9t+7/qTcB2JLTuiwM9Gqg5sDDnzPlcZSa7GnIU0MLQIDAQABoxkwFzAVBgNVHREEDjAMggp3ZWItZWlkLmV1MA0GCSqGSIb3DQEBBQUAA4IBAQAYGkBhTlet47uw3JYunYo6dj4nGWSGV4x6LYjCp5QlAmGd28HpC1RFB3ba+inwW8SP69kEOcB0sJQAZ/tV90oCATNsy/Whg/TtiHISL2pr1dyBoKDRWbgTp8jjzcp2Bj9nL14aqpj1t4K1lcoYETX41yVmyyJu6VFs80M5T3yikm2giAhszjChnjyoT2kaEKoua9EUK9SS27pVltgbbvtmeTp3ZPHtBfiDOATL6E03RZ5WfMLRefI796a+RcznnudzQHhMSwcjLpMDgIWpUU4OU7RiwrU+S3MrvgzCjkWh2MGu/OGLB+d3JZoW+eCvigoshmAsbJCMLbh4N78BCPqk';
    private const WRONG_PURPOSE_CERT = 'MIIEBDCCA2WgAwIBAgIQGIgoZxFL7VZbyFH7MAVEkTAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE4MTAxODA5MjcyM1oXDTIzMTAxNzIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT3SZB34CUGYhQyLsLd9b2ihv35q7NT47Id9ugLIdgg3NSFDccH6rV16D2m8DKfuD2mn3V6QdaaZnbWF4YdDK1W0C9kLNsB70ob//y39pugMftepmQpJcBGPqug81tf5jujggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFPhJx7ro54+N8r2ByiZXzZyWBbjFMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsG/wUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgFi5XSCFGgsc8SKLWwMBWS0nu/20FjEqh6OGvsI4iPctNDkinsxcYgARdfqPsNnDX+KjALKPEKZCLKRixGL2kPLMgJCAQFXP9gstThxlj/1Q5YFb7KWhPWFiKgQEi9JdvxJQNXLkWV9onEh96mRFgv4IJJpGazuoSMZtzNpyBxmM0dwnxOf';
    private const WRONG_POLICY_CERT = 'MIIEATCCA2OgAwIBAgIQOWkBWXNDJm1byFd3XsWkvjAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE4MTAxODA5NTA0N1oXDTIzMTAxNzIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR5k1lXzvSeI9O/1s1pZvjhEW8nItJoG0EBFxmLEY6S7ki1vF2Q3TEDx6dNztI1Xtx96cs8r4zYTwdiQoDg7k3diUuR9nTWGxQEMO1FDo4Y9fAmiPGWT++GuOVoZQY3XxijggHBMIIBvTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBFBgNVHSAEPjA8MDAGCSsGAQQBzh8BAzAjMCEGCCsGAQUFBwIBFhVodHRwczovL3d3dy5zay5lZS9DUFMwCAYGBACPegECMB8GA1UdEQQYMBaBFDM4MDAxMDg1NzE4QGVlc3RpLmVlMB0GA1UdDgQWBBTkLL00CRAVTDEpocmV+W4m2CbmwDBhBggrBgEFBQcBAwRVMFMwUQYGBACORgEFMEcwRRY/aHR0cHM6Ly9zay5lZS9lbi9yZXBvc2l0b3J5L2NvbmRpdGlvbnMtZm9yLXVzZS1vZi1jZXJ0aWZpY2F0ZXMvEwJFTjAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwHwYDVR0jBBgwFoAUwISZKcROnzsCNPaZ4QpWAAgpPnswcwYIKwYBBQUHAQEEZzBlMCwGCCsGAQUFBzABhiBodHRwOi8vYWlhLmRlbW8uc2suZWUvZXN0ZWlkMjAxODA1BggrBgEFBQcwAoYpaHR0cDovL2Muc2suZWUvVGVzdF9vZl9FU1RFSUQyMDE4LmRlci5jcnQwCgYIKoZIzj0EAwQDgYsAMIGHAkIB9VLJjHbS2bYudRatkEeMFJAMKbJ4bAVdh0KlFxWASexF5ywpGl43WSpB6QAXzNEBMe1FIWiOIud44iexNWO1jgACQQ1+M+taZ4hyWqSNW5DCIiUP7Yu4WvH3SUjEqQHbOQshyMh5EM1pVcvOn/ZgOxLt6ETv9avnhVMw2zTd1b8u4EFk';

    private const OLD_MOBILE_ID_CERT = 'MIIE/TCCAuWgAwIBAgIQKbCN+05vfp1XOXVu6HMXRTANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxFzAVBgNVBAMMDkVTVEVJRC1TSyAyMDE1MB4XDTE2MDUxNjA3MjMyNloXDTIxMDUxNjIwNTk1OVowgZsxCzAJBgNVBAYTAkVFMRswGQYDVQQKDBJFU1RFSUQgKE1PQklJTC1JRCkxFzAVBgNVBAsMDmF1dGhlbnRpY2F0aW9uMSAwHgYDVQQDDBdLQVNTLEFSVFVSSSwzNjAxMjM0NTY3ODENMAsGA1UEBAwES0FTUzEPMA0GA1UEKgwGQVJUVVJJMRQwEgYDVQQFEwszNjAxMjM0NTY3ODBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBMstpyGLcAEXkctwF8TkyPUl1IizQb6nBvfEIaayMmNzZFRCNLZfV6z4AXJN58Mjs4d4RXsARU1vjBsi8yJMaCjggE9MIIBOTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIEsDBbBgNVHSAEVDBSMFAGCisGAQQBzh8BAwMwQjAdBggrBgEFBQcCAjARDA9Db250cmFjdCAxLjExLTkwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL2NwczAfBgNVHREEGDAWgRRoZWlra2kua2l0dEBlZXN0aS5lZTAdBgNVHQ4EFgQUkNR/r9m77o9Gsp04JFIBqEATVGQwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMB8GA1UdIwQYMBaAFLOriLyZ1WKkhSoIzbQdcjuDckdRMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly93d3cuc2suZWUvY3Jscy9lc3RlaWQvZXN0ZWlkMjAxNS5jcmwwDQYJKoZIhvcNAQELBQADggIBAEJCCMR6IQ/Xncjyj9jtlFm1UBuf4g71GfSQMtL1g3ZxLBc77aKwBBtTuOTmPDUdY5+xA5dDfj6nFRdZZwWedps9Tm5T98G+y0477TCfP29UlnpQ55EtdXGdgzeDMlCpmRpsu2YceajdpQncp6A8tJsG+hW733O6W2dqrQV2e7Dnofm20KVHHlUa+ma+pGvaHDYXHgYAD1o58Ro+JHy7Bw3jo4Lg+j/CuBzTk4T6D05Ybnvv58/PBrPjASwKVhjNNvHYwgDmeGzQKocmDWUSRjTiWAxP9PYxwuiP2epoypyv9VPJEe3dy3EWgY+iPfMN2BuFdmZtKSHdWSeqCK+jro4kzjWrGYY+JbxSYmfF3GWWAj5sq/+/S2SgiFWGHdvtr1kVr7DaLDmz8N/QyrNjVVz4bYkzj9OPM7ofJs1QDE/2yGCkpJ628zB1ATpEjtVsit5hti0d3k1cIBTbtiUuSrOGHTyxwRenvIZ/MckvLFmTKZ6m255ASjtwqTf2Z+Jo13Adr5zhRvQvY+qGfZb/E4KhVSrcUI8OgTXzkPGIdm6tYETKqmdgevG16noPxzmzf6DJsjnbrOwuEhRykUzSRWO+h0pA7lvjLN8SKbCn/uWARN1XsbarA0yAnW484Gsu8psOaGpZ+VzM7z5/yv/BY2aTPP0hIeI0cqRtko7Zs6vH';
    private const NEW_MOBILE_ID_CERT = 'MIIFmDCCA4CgAwIBAgIQMwcy8Yggv2lfTTKLQOhNYTANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxFzAVBgNVBAMMDkVTVEVJRC1TSyAyMDE1MB4XDTIwMDgzMTE3MjUzMVoXDTI1MDgzMTIwNTk1OVowcTELMAkGA1UEBhMCRUUxIzAhBgNVBAMMGkvDlVZFUlNBUixNQVRJLDM4MzA5MTQwNDIwMRIwEAYDVQQEDAlLw5VWRVJTQVIxDTALBgNVBCoMBE1BVEkxGjAYBgNVBAUTEVBOT0VFLTM4MzA5MTQwNDIwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJcgIjZEEIyIMGVli1xp88YlS8PnWBCcXdBiBTDNiVT/4OlTTteBBIePn2vKWOgUNDOWyFsBQRPy93Pig2thAzqOCAgMwggH/MAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgOIMHIGA1UdIARrMGkwXQYJKwYBBAHOHwEDMFAwLwYIKwYBBQUHAgEWI2h0dHBzOi8vd3d3LnNrLmVlL3JlcG9zaXRvb3JpdW0vQ1BTMB0GCCsGAQUFBwICMBEaD0NvbnRyYWN0IDEuMTEtOTAIBgYEAI96AQIwIQYDVR0RBBowGIEWbWF0aS5rb3ZlcnNhckBlZXN0aS5lZTAdBgNVHQ4EFgQUaNW6n29aMRbULPtIyvmRq50g8g8wHwYDVR0jBBgwFoAUs6uIvJnVYqSFKgjNtB1yO4NyR1EwagYIKwYBBQUHAQEEXjBcMCcGCCsGAQUFBzABhhtodHRwOi8vYWlhLnNrLmVlL2VzdGVpZDIwMTUwMQYIKwYBBQUHMAKGJWh0dHA6Ly9jLnNrLmVlL0VTVEVJRC1TS18yMDE1LmRlci5jcnQwYQYIKwYBBQUHAQMEVTBTMFEGBgQAjkYBBTBHMEUWP2h0dHBzOi8vc2suZWUvZW4vcmVwb3NpdG9yeS9jb25kaXRpb25zLWZvci11c2Utb2YtY2VydGlmaWNhdGVzLxMCRU4wPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL3d3dy5zay5lZS9jcmxzL2VzdGVpZC9lc3RlaWQyMDE1LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAFvYmmaeNvh6vakizkv6HvXYXXDvTIVA7Z3WsXN9ZffvqiqM6wg9iIBiWjUE5qKh0sVa6qlxTHJ90keltgWsLkPbyCeJvsl7npI+/3NvHjwR83dHzmi8V21zLAVwg3nGpbklg2uTPAagQfRwa91D3+SPu/2Uo6a/vwJVTaMZP+PEHEkCmNuwPAECgnniNgcwlCK0mhNK9urDWewsDcZqRIi61QyQzHde9l0IUlTcI8nPzIma5f831xVXGqi98WQZpqfHsdPL14wwAP5UjszvDe3DOvx0eARhoSrm8MLj3Y9oN82oM0XBIc6uRw0KNp8lunHMIAL2b30ULJkXMLLdA/FK4KS2Mvlt+dO3x+tqKUGX4wrxPtNmWvvLFKfPpzjLKDl/JA6fBcD2LHcKSDMK8Jgcokl3tzI8zG0RKy3yDCpA+c3CP7pIDLBb0fpNzjUAtTS72mgAzRbFNXctN05uekYmThU2Z71MvUCw0JixN6G7DmiOe3cp9kA01f0RBlM76f2x6YmZ7XCdI0JNQm8SpyctVX/2Sbed0kbjpOV05CFEtWWYlBO3oHf7Sf0jqYrs3SN999MHHCg4wdsWUJiGuILyMJi+gQphID/PgjDW9qxLd0kqK1cBLKybwgBScdt5KZjrTKYWOSTwvh5FhFKVVwsCMeOh/+ojKWhX6uKhwMOQ=';
    private const EXPIRED_RSA_CERT = 'MIIE3DCCA8SgAwIBAgIQbLnhZj25xUtSW9CfBn46KjANBgkqhkiG9w0BAQUFADBkMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEAwwORVNURUlELVNLIDIwMTExGDAWBgkqhkiG9w0BCQEWCXBraUBzay5lZTAeFw0xMzEwMTQxMTA4MTVaFw0xODEwMTEyMDU5NTlaMIGPMQswCQYDVQQGEwJFRTEPMA0GA1UECgwGRVNURUlEMRcwFQYDVQQLDA5hdXRoZW50aWNhdGlvbjEgMB4GA1UEAwwXS0lUVCxIRUlLS0ksMzc3MTIzMDAyNTUxDTALBgNVBAQMBEtJVFQxDzANBgNVBCoMBkhFSUtLSTEUMBIGA1UEBRMLMzc3MTIzMDAyNTUwggEjMA0GCSqGSIb3DQEBAQUAA4IBEAAwggELAoIBAQBopcNoApF/o+YyVcHaonVhCbUYfUhDtoP2VDOKXNytBNIFO5uEL86mMOcfTURfOssrpvQBVgKWgQ0wjhq09qkfPJM9NbPz0VytcsGARKSNcPh1BKgnUnfd0M6SwSl1rFl2zvbDBfZTMDtQbROS4eV1wBXwa8XeHqQmTOZK/4mv+6fj0q/LzPmxUHP/LJbyjm07MAVzTAGFvanICPdTY9YQUyNCtp+r8RxjNEk/FjVDi9zgER7Tg/v/VEnjUdZG4pLZXnV+4EsBcH2Y/XoPq3Ou0ts3IG02iz83UFR0o3TYQnHnW9fMwToJRQzS3Bnd+NZee+yZZNKOUvxmn8f4dsDdAgR3CME3o4IBWzCCAVcwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBLAwUQYDVR0gBEowSDBGBgsrBgEEAc4fAQEDAzA3MBIGCCsGAQUFBwICMAYaBG5vbmUwIQYIKwYBBQUHAgEWFWh0dHA6Ly93d3cuc2suZWUvY3BzLzAfBgNVHREEGDAWgRRoZWlra2kua2l0dEBlZXN0aS5lZTAdBgNVHQ4EFgQUC8nhz1ziuRJnO6hJIBYthupzYkYwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMCIGCCsGAQUFBwEDBBYwFDAIBgYEAI5GAQEwCAYGBACORgEEMB8GA1UdIwQYMBaAFHtq8lVQXLjZegiHQa76ois9W1d2MEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly93d3cuc2suZWUvcmVwb3NpdG9yeS9jcmxzL2VzdGVpZDIwMTEuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQBV7ohEG05MXcxHEeXOb2hNuLrVVT2dhOVwp21M13sOsG9l/GN8KEUR4JQcJo4zEK49zHCaA1qKg+4/mubWfMKz5eUS9njs7cuit2FjlTJUrm7ye9dKndGiv5o4T4ycvbUF4NJ6AvxXZLolfLTaF6Ge/c15Jz1WmBv0x+0C00d0qWkE3VVjwqYxUw9gJlWfbLLxqsT1pUXaf9JcsxdKXkhKKr9eQ7r00PwbARkKyeU/ylHGfOQlZeGXfyWxX1q1ZALicwJe6/UbQTqQeLn5Mviw/49H2rLb9BImFIJ30QYBlj9SGSHSZ5k11XPRaw2GfLrgoBqOjMUyKhfRxqJwb/xL';
    private const EXPIRED_ECDSA_CERT = 'MIIF0TCCA7mgAwIBAgIQMBVFXroEt3hZ8FHcKKE65TANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxFzAVBgNVBAMMDkVTVEVJRC1TSyAyMDE1MB4XDTE3MTAyNTA4NTcwMFoXDTIxMDIxMDIxNTk1OVowgYsxCzAJBgNVBAYTAkVFMQ8wDQYDVQQKDAZFU1RFSUQxFzAVBgNVBAsMDmF1dGhlbnRpY2F0aW9uMR4wHAYDVQQDDBVUT09NLE1BUlQsMzc2MDIwNDAzMzQxDTALBgNVBAQMBFRPT00xDTALBgNVBCoMBE1BUlQxFDASBgNVBAUTCzM3NjAyMDQwMzM0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAExS1YQQBDLVvOi0a2GA5Y34AXODpx0AL8eKDOB7BjwBc/FAyVExhfb6O+lT5Tnaec3GnT4JNRyeV8d82L8cyOgFn4PWc+5cjFdmcZjJbtCvgyBOQQ831tteIDL2XSrvZEo4ICBDCCAgAwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCA4gwUwYDVR0gBEwwSjA+BgkrBgEEAc4fAQEwMTAvBggrBgEFBQcCARYjaHR0cHM6Ly93d3cuc2suZWUvcmVwb3NpdG9vcml1bS9DUFMwCAYGBACPegECMB8GA1UdEQQYMBaBFG1hcnQudG9vbS4zQGVlc3RpLmVlMB0GA1UdDgQWBBSzneoLqtqbvHvJ19cjhp2XR5ovQTAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwHwYDVR0jBBgwFoAUs6uIvJnVYqSFKgjNtB1yO4NyR1EwYQYIKwYBBQUHAQMEVTBTMFEGBgQAjkYBBTBHMEUWP2h0dHBzOi8vc2suZWUvZW4vcmVwb3NpdG9yeS9jb25kaXRpb25zLWZvci11c2Utb2YtY2VydGlmaWNhdGVzLxMCRU4wagYIKwYBBQUHAQEEXjBcMCcGCCsGAQUFBzABhhtodHRwOi8vYWlhLnNrLmVlL2VzdGVpZDIwMTUwMQYIKwYBBQUHMAKGJWh0dHA6Ly9jLnNrLmVlL0VTVEVJRC1TS18yMDE1LmRlci5jcnQwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL3d3dy5zay5lZS9jcmxzL2VzdGVpZC9lc3RlaWQyMDE1LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAOXTvktUXqPgaK/uxzgH0xSEYClBAWIQaNgpqY5lwsQtgQnpfKlsADqMZxCp7UuuMvQmpDbBxv1kIr0oG1uUXrUtPw81XOH1ClwPPXWpg9VRTAetNbHTBbHDyzuXQMNeDmrntChs+BteletejGD+aYG39HGMlrMbGQZOgvQrpYHMDek0ckCPEsZRXqUP0g7Ie7uBQhz5At7l4EDAeOW8xGoI6t+Ke4GedccXKef60w2ZIIDzvOFHPTc6POCsIlFtF/nCKwVi7GoQKjbUbM5OdBLZ0jyLq2LvzZuT86Jo8wObziuSzApGlBexHAqLrR83q+/Xl61yPnFf3w2kAfS9kBjeunzTH7Jm3pNT3Zq9JRLvEDqtpOPqr4zm9nG6OSghFU6tySkpQ5HiakGpMcnt5o5KuXhQ+Dg317tdXPyQkSiuJ9NfEBW0ijrwO12SVRzYo/jRl4ZQUkAEEUSMEsC6gTsZypPdIsLDVoQWTytHDU89s1xJDn4HulPl12dFnrhlLeX4RxOjDxppZxdjBU0FoJoDB0qwEAN2TMAPJWh+Pp9mFuS/u0dht9sKvAkpx+o0Z7v7QMz03XlzCHOLTIK+f81Rjokl8f+wiog5Ojj0wZkDe6DuQC9L5uDey3PJHv3naVovhs7jrEJu+yrsLue/OHhAgWRh2S75/wlVPHPEE44k=';
    private const REVOKED_CERT = 'MIIERDCCA6agAwIBAgIQSs8/WoDixVxbKRhNnF/GEzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE4MDYxOTE0NTA1M1oXDTIwMDEwMjIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR/jopNG3KL0ZQUvO4OGSvcaqUtFDm3azOtsM2VRp666r0d36Zh0Zx/xej8f+SzEfWvvDT1HQLo3USiSbYn1FyNHTNxifV+Zvf6StXJAkdu24d1UvKbf+LylglO/yS7o4ijggIEMIICADAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5F/AQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFEQA6/1GXJtp+6czUzorhEJ7B95pMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezB/BggrBgEFBQcBAQRzMHEwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MEEGCCsGAQUFBzAChjVodHRwczovL3NrLmVlL3VwbG9hZC9maWxlcy9URVNUX29mX0VTVEVJRDIwMTguZGVyLmNydDAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vYy5zay5lZS90ZXN0X2VzdGVpZDIwMTguY3JsMAoGCCqGSM49BAMEA4GLADCBhwJBcmcfLC+HcSJ6BuRrDGL+K+7BAW8BfAiiWWAuBV4ebLkbbAWmkc9dSKgr4BEGEt90xDTQ85yW4SjGulFXu9C3yQsCQgETaXTs3Hp6vDAcQYL8Bx4BO3DwJbDuD4BUJyT0+9HQiFCQmTQ4xrNjeaeOwRWyMOM9z5ORMeJCiQUyil1x4YPIbg==';

    protected function setUp(): void
    {
        parent::setUp();
        // Ensure that the certificates do not expire.
        $this->mockDate("2021-08-01");
    }

    protected function tearDown(): void
    {
        Dates::resetMockedCertificateValidatorDate();
    }

    public function testWhenCertificateFieldIsMissingThenParsingFails(): void
    {
        $token = $this->removeTokenField(self::AUTH_TOKEN, "unverifiedCertificate");

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'unverifiedCertificate' field is missing, null or empty");
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificateFieldIsEmptyThenParsingFails(): void
    {
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", "");

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'unverifiedCertificate' field is missing, null or empty");
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificateFieldIsArrayThenParsingFails(): void
    {
        try {
            $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", [1, 2, 3, 4]);
        } catch (UnexpectedValueException $e) {
            $this->assertEquals("Error parsing Web eID authentication token: 'unverifiedCertificate' is array, string expected", $e->getMessage());
        }
    }

    public function testWhenCertificateFieldIsNumberThenParsingFails(): void
    {
        try {
            $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", 1234);
        } catch (UnexpectedValueException $e) {
            $this->assertEquals("Error parsing Web eID authentication token: 'unverifiedCertificate' is integer, string expected", $e->getMessage());
        }
    }

    public function testWhenCertificateFieldIsNotBase64ThenParsingFails(): void
    {
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", "This is not a certificate");

        $this->expectException(CertificateDecodingException::class);
        $this->expectExceptionMessage("'unverifiedCertificate' decode failed");
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificateFieldIsNotCertificateThenParsingFails(): void
    {
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", "VGhpcyBpcyBub3QgYSBjZXJ0aWZpY2F0ZQ");

        $this->expectException(CertificateDecodingException::class);
        $this->expectExceptionMessage("'unverifiedCertificate' decode failed");
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificatePurposeIsMissingThenValidationFails(): void
    {
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", self::MISSING_PURPOSE_CERT);

        $this->expectException(UserCertificateMissingPurposeException::class);
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificatePurposeIsWrongThenValidationFails(): void
    {
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", self::WRONG_PURPOSE_CERT);

        $this->expectException(UserCertificateWrongPurposeException::class);
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificatePolicyIsWrongThenValidationFails(): void
    {
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", self::WRONG_POLICY_CERT);

        $this->expectException(UserCertificateDisallowedPolicyException::class);
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificatePolicyIsDisallowedThenValidationFails(): void
    {
        $validatorWithDisallowedESTEIDPolicy = AuthTokenValidators::getAuthTokenValidatorWithDisallowedESTEIDPolicy();

        $this->expectException(UserCertificateDisallowedPolicyException::class);
        $validatorWithDisallowedESTEIDPolicy->validate($this->validAuthToken, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenUsingOldMobileIdCertificateThenValidationFails(): void
    {
        $this->mockDate("2021-03-01");

        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", self::OLD_MOBILE_ID_CERT);

        $this->expectException(UserCertificateDisallowedPolicyException::class);
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenUsingNewMobileIdCertificateThenValidationFails(): void
    {
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", self::NEW_MOBILE_ID_CERT);

        $this->expectException(UserCertificateMissingPurposeException::class);
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificateIsExpiredRsaThenValidationFails(): void
    {
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", self::EXPIRED_RSA_CERT);

        $this->expectException(CertificateExpiredException::class);
        $this->expectExceptionMessage("User certificate has expired");
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificateIsExpiredEcdsaThenValidationFails(): void
    {
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", self::EXPIRED_ECDSA_CERT);

        $this->expectException(CertificateExpiredException::class);
        $this->expectExceptionMessage("User certificate has expired");
        $this->validator->validate($token, self::VALID_CHALLENGE_NONCE);
        $this->expectNotToPerformAssertions();
    }

    // Subject certificate validity:
    // - not before: Thu Oct 18 12:50:47 EEST 2018
    // - not after: Wed Oct 18 00:59:59 EEST 2023
    // Issuer certificate validity:
    // - not before: Thu Sep 06 12:03:52 EEST 2018
    // - not after: Tue Aug 30 15:48:28 EEST 2033

    public function testWhenUserCertificateIsNotYetValidThenValidationFails()
    {
        $this->mockDate("2018-10-17");

        $this->expectException(CertificateNotYetValidException::class);
        $this->validator->validate($this->validAuthToken, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenTrustedCaCertificateIsNotYetValidThenValidationFails()
    {
        $this->mockDate("2018-08-17");

        $this->expectException(CertificateNotYetValidException::class);
        $this->validator->validate($this->validAuthToken, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenUserCertificateIsNoLongerValidThenValidationFails()
    {
        $this->mockDate("2026-10-19");

        $this->expectException(CertificateExpiredException::class);
        $this->expectExceptionMessage("User certificate has expired");
        $this->validator->validate($this->validAuthToken, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenTrustedCaCertificateIsNoLongerValidThenValidationFails()
    {
        $this->mockDate("2033-10-19");

        $this->expectException(CertificateExpiredException::class);
        $this->expectExceptionMessage("Trusted CA certificate has expired");
        $this->validator->validate($this->validAuthToken, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificateIsRevokedThenOcspCheckFails(): void
    {
        $this->mockDate("2020-01-01");
        $validatorWithOcspCheck = AuthTokenValidators::getAuthTokenValidatorWithOcspCheck();
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", self::REVOKED_CERT);

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: Exception: User certificate has been revoked: Revocation reason: unspecified");

        $validatorWithOcspCheck->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificateIsRevokedThenOcspCheckWithDesignatedOcspServiceFails(): void
    {
        $this->markTestSkipped("A new designated test OCSP responder certificate was issued whose validity period no longer overlaps with the revoked certificate");
        $this->mockDate("2020-01-01");

        $validatorWithOcspCheck = AuthTokenValidators::getAuthTokenValidatorWithDesignatedOcspCheck();
        $token = $this->replaceTokenField(self::AUTH_TOKEN, "unverifiedCertificate", self::REVOKED_CERT);

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: Exception: User certificate has been revoked");

        $validatorWithOcspCheck->validate($token, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenCertificateCaIsNotPartOfTrustChainThenValidationFails(): void
    {
        $validatorWithWrongTrustedCA = AuthTokenValidators::getAuthTokenValidatorWithWrongTrustedCertificate();

        $this->expectException(CertificateNotTrustedException::class);
        $validatorWithWrongTrustedCA->validate($this->validAuthToken, self::VALID_CHALLENGE_NONCE);
    }

    private function mockDate(string $date)
    {
        Dates::setMockedCertificateValidatorDate(new DateTime($date));
    }
}
