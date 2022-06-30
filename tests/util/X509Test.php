<?php

namespace web_eid\web_eid_authtoken_validation_php\util;

use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;
use PHPUnit\Framework\TestCase;

class X509Test extends TestCase
{
    public function testValidateSubjectPropsFromCertFile(): void
    {
        $cert = Certificates::getMariLiisEsteid2015Cert();
        $this->assertEquals("EE", $cert->getSubjectProp("C"));
        $this->assertEquals("MÄNNIK,MARI-LIIS,61710030163", $cert->getSubjectProp("CN"));
    }

    public function testValidateSubjectPropsFromCertDerBase64(): void
    {
        $x509 = new X509();
        $x509->loadX509("MIIEFjCCAv6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBfMQswCQYDVQQGEwJFRTERMA8GA1UECAwISGFyanVtYWExEDAOBgNVBAcMB1RhbGxpbm4xDTALBgNVBAoMBERlbW8xDTALBgNVBAsMBERlbW8xDTALBgNVBAMMBERlbW8wHhcNMjIwNjI4MDcxODU1WhcNMzIwNjI1MDcxODU1WjCBgjELMAkGA1UEBhMCRUUxETAPBgNVBAgMCEhhcmp1bWFhMQ0wCwYDVQQHDAREZW1vMQ0wCwYDVQQKDAREZW1vMQ0wCwYDVQQLDAREZW1vMRIwEAYDVQQDDAlUZXN0IFVzZXIxHzAdBgkqhkiG9w0BCQEWEGluZm9AZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCu+XG53DBFtBk8eXrP7hLU+dyqCKSBC9R3eTh184jFkr5+sqMgIA+w9A7XfGhpelbbXY9FTzERlzSbjbTkSbnJxtfqDXTfoXZ7sAG9n7wdohwDOM8xhVSpWDPhf+nVTCji6hCbCpnEtvSs+8cYzS0oa++j36dNwGAm1jboshPrPVRke4fiwGM4bSiiB15doUZF8F6avyCHzg1yKa2OWx9pRXu5DfZMDWMxq0tHfo1O7/X1Ujyq7EH8fd1M5wEVCTO6rp8yhdHwvoxe14OHZ14qXoMjco0eLTDZVIQlt2spKlmK9fw1OYKCntGS9j2GPaWOy52fa3Vc7aRDwPpFp8OjAgMBAAGjgbgwgbUwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFB2mAM04p+p1JI6WlGLg0Htes1j9MB8GA1UdIwQYMBaAFCt34kgLKoYOh/2V1qubNkwO0lqSMAsGA1UdDwQEAwIEMDATBgNVHSUEDDAKBggrBgEFBQcDATAYBgNVHREEETAPgg0qLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBwXn6fYP+sCH6WEFAo/Q2bJgikdMXQ6//5P2mZCvoMBsMYWm34AyZiaA5Xdhy4lVwJNJ7m9jApoC7PFuAwssjqWZBKlCrKJECbxasLnoGO8OQpQ43WdvhEO4YU91jfknhPQ8shqAVFua0hKPSdx+1wocrQhGm+7xPK7Caq/XV+ZE9P59K/hyqY3ZYU3vVYUQJm1IJN9R1vm3Lx9vZphBu6MnAbivB6rUwIh68PBGZhofS3ESQrIsie8IPxq2L4H6UUCY9297QX+3XoL8HaYBRsk7AwtG5XHM3xjvuI1kTDV3eeMe1zeXSPR8ltj+7/6t3oc8bkRLg2BQ8deRmZbFXn");
        $this->assertEquals("EE", $x509->getSubjectProp("C"));
        $this->assertEquals("Test User", $x509->getSubjectProp("CN"));
    }

}