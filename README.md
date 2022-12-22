# web-eid-authtoken-validation-php

![European Regional Development Fund](https://github.com/open-eid/DigiDoc4-Client/blob/master/client/images/EL_Regionaalarengu_Fond.png)

web-eid-authtoken-validation-php is a PHP library for issuing challenge nonces and validating Web eID authentication tokens during secure authentication with electronic ID (eID) smart cards in web applications.

The logic of this repository is based on the [Java library](https://github.com/web-eid/web-eid-authtoken-validation-java). We also draw inspiration from the [PHP library](https://github.com/Muzosh/web-eid-authtoken-validation-php) created by Petr Muzikant and used some of his code.

More information about the Web eID project is available on the project [website](https://web-eid.eu/).

# Quickstart

Complete the steps below to add support for secure authentication with eID cards to your PHP web application back end. Instructions for the front end are available [here](https://github.com/web-eid/web-eid.js).

A PHP web application that uses Composer to manage packages is needed for running this quickstart.

## 1. Add the library to your project

Add the following lines to `composer.json` to include the Web eID authentication token validation library in your project:

```json
"require": {
    "web-eid/web-eid-authtoken-validation-php": "dev-main",
    "web-eid/ocsp-php": "dev-main",
},
"repositories": [
    {
        "type": "vcs",
        "url": "https://github.com/web-eid/web-eid-authtoken-validation-php.git"
    },
    {
        "type": "vcs",
        "url": "https://github.com/web-eid/ocsp-php.git"
    }
]
```

### Logging

For logging, you have to create `LoggerInterface` and use it on `AuthTokenValidatorBuilder` initialization.

Example logger interface with Monolog:
```php
use Monolog\Level;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

...
$log = new Logger("general");
$log->pushHandler(new StreamHandler("/some/path/app.log", Level::Debug));

return (new AuthTokenValidatorBuilder($log))
      ->withSiteOrigin(new Uri("https://example.org"))
      ->withTrustedCertificateAuthorities(...self::trustedIntermediateCACertificates())
      ->build();
```
Read more about [LoggerInterface](https://www.php-fig.org/psr/psr-3/) and take a look from examples directory.

## 2. Configure the challenge nonce store

The validation library needs to generate authentication challenge nonces and store them for later validation in the challenge nonce store. Overview of challenge nonce usage is provided in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1). The challenge nonce generator will be used in the REST endpoint that issues challenges.

```php
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceGenerator;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceGeneratorBuilder;

...
public function generator(): ChallengeNonceGenerator
{
    return (new ChallengeNonceGeneratorBuilder())
      ->withNonceTtl(300) // challenge nonce TTL in seconds, default is 300 (5 minutes)
      ->build();
}
...
```

PHP Session is been used for storing the challenge nonce.

## 3. Add trusted certificate authority certificates

You must explicitly specify which **intermediate** certificate authorities (CAs) are trusted to issue the eID authentication and OCSP responder certificates. CA certificates can be loaded from resources.

First, copy the trusted certificates, for example `ESTEID-SK_2015.der.cer` and `ESTEID2018.der.cer`, to `certificates/` folder, then load the certificates as follows:

```php
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateLoader;

...
public function trustedIntermediateCACertificates(): array
{
    return CertificateLoader::loadCertificatesFromResources(
        __DIR__ . "/../certificates/ESTEID2018.cer", __DIR__ . "/../certificates/ESTEID-SK_2015.cer"
    );
}
...
```

## 4. Configure the authentication token validator

Once the prerequisites have been met, the authentication token validator itself can be configured. The mandatory parameters are the website origin and trusted certificate authorities. The authentication token validator will be used in the login processing component of your web application authentication framework

```php
use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidatorBuilder;

...
public function tokenValidator(): AuthTokenValidator
{
    return (new AuthTokenValidatorBuilder())
      ->withSiteOrigin(new Uri("https://example.org"))
      ->withTrustedCertificateAuthorities(...self::trustedIntermediateCACertificates())
      ->build();
}
...
```

## 5. Add a REST endpoint for issuing challenge nonces

A REST endpoint that issues challenge nonces is required for authentication. The endpoint must support `GET` requests.

In the following example, we are using the AltoRouter to implement the endpoint

```php
class Router
{
    public function init()
    {

        $router = new AltoRouter();
        $router->setBasePath("");
        
        $router->map("GET", "/", ["controller" => "Pages", "method" => "login"]);
        $router->map("GET", "/nonce", ["controller" => "Auth", "method" => "getNonce"]);
        
        $match = $router->match();

        if (!$match) {
            // Redirect to main
            header('Location: /');
            return;
        }


        $controller = new $match["target"]["controller"];
        $method = $match["target"]["method"];

        call_user_func([$controller, $method], $match["params"], []);

    }
}

class Auth
{
    ...
    public function getNonce()
    {

        try {
            header("Content-Type: application/json; charset=utf-8");
            $generator = $this->generator();
            $challengeNonce = $generator->generateAndStoreNonce();
            $responseArr["nonce" => $challengeNonce->getBase64EncodedNonce()];
            echo json_encode($responseArr);
        } catch (Exception $e) {
            header("HTTP/1.0 500 Internal Server Error");
            echo $e->getMessage();
        }
    }
    ...
}

```

## 6. Implement authentication

Authentication consists of calling the validate() method of the authentication token validator. The internal implementation of the validation process is described in more detail below and in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

```php
use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateData;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceStore;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
...

private function getPrincipalNameFromCertificate(X509 $userCertificate): string
{
    try {
        return CertificateData::getSubjectGivenName($userCertificate) . " " . CertificateData::getSubjectSurname($userCertificate);
    } catch (Exception $e) {
        return CertificateData::getSubjectCN($userCertificate);
    }
}
...

try {

    /* Get and remove nonce from store */
    $challengeNonce = (new ChallengeNonceStore())->getAndRemove();

    try {

        // Build token validator
        $tokenValidator = $this->tokenValidator();

        // Validate token
        $cert = $tokenValidator->validate(new WebEidAuthToken($authToken), $challengeNonce->getBase64EncodedNonce());

        session_regenerate_id();

        $subjectName = $this->getPrincipalNameFromCertificate($cert);
        $result = [
            'sub' => $subjectName
        ];

        echo json_encode($result);

    } catch (Exception $e) {
        // Handle exception
    }

} catch (ChallengeNonceExpiredException $e) {
    // Handle exception
}
...
```
See the complete example from the ***examples*** directory.


# Table of contents

- [Quickstart](#quickstart)
- [Introduction](#introduction)
- [Authentication token validation](#authentication-token-validation)
  - [Basic usage](#basic-usage)
  - [Extended configuration](#extended-configuration)
    - [Certificates' <em>Authority Information Access</em> (AIA) extension](#certificates-authority-information-access-aia-extension)
  - [Possible validation errors](#possible-validation-errors)
  - [Stateful and stateless authentication](#stateful-and-stateless-authentication)
- [Challenge nonce generation](#challenge-nonce-generation)
  - [Basic usage](#basic-usage-1)
  - [Extended configuration](#extended-configuration-1)  
- [Example implementation](#example-implementation)
- [Code formatting](#code-formatting)
- [Testing](#testing)

# Introduction

The Web eID authentication token validation library for PHP contains the implementation of the Web eID authentication token validation process in its entirety to ensure that the authentication token sent by the Web eID browser extension contains valid, consistent data that has not been modified by a third party. It also implements secure challenge nonce generation as required by the Web eID authentication protocol. It is easy to configure and integrate into your authentication service.

The authentication protocol, authentication token format, validation requirements and challenge nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).


# Authentication token validation

The authentication token validation process consists of two stages:

- First, **user certificate validation**: the validator parses the token and extracts the user certificate from the *unverifiedCertificate* field. Then it checks the certificate expiration, purpose and policies. Next it checks that the certificate is signed by a trusted CA and checks the certificate status with OCSP.
- Second, **token signature validation**: the validator validates that the token signature was created using the provided user certificate by reconstructing the signed data `hash(origin)+hash(challenge)` and using the public key from the certificate to verify the signature in the `signature` field. If the signature verification succeeds, then the origin and challenge nonce have been implicitly and correctly verified without the need to implement any additional security checks.

The website back end must lookup the challenge nonce from its local store using an identifier specific to the browser session, to guarantee that the authentication token was received from the same browser to which the corresponding challenge nonce was issued. The website back end must guarantee that the challenge nonce lifetime is limited and that its expiration is checked, and that it can be used only once by removing it from the store during validation.

## Basic usage

As described in section *[4. Configure the authentication token validator](#4-configure-the-authentication-token-validator)*, the mandatory authentication token validator configuration parameters are the website origin and trusted certificate authorities.

**Origin** must be the URL serving the web application. Origin URL must be in the form of `"https://" <hostname> [ ":" <port> ]`  as defined in [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Location/origin) and not contain path or query components. Note that the `origin` URL must not end with a slash `/`.

The **trusted certificate authority certificates** are used to validate that the user certificate from the authentication token and the OCSP responder certificate is signed by a trusted certificate authority. Intermediate CA certificates must be used instead of the root CA certificates so that revoked CA certificates can be removed. Trusted certificate authority certificates configuration is described in more detail in section *[3. Add trusted certificate authority certificates](#3-add-trusted-certificate-authority-certificates)*.

Before validation, the previously issued **challenge nonce** must be looked up from the store using an identifier specific to the browser session. The challenge nonce must be passed to the `validate()` method in the corresponding parameter. Setting up the challenge nonce store is described in more detail in section *[2. Configure the challenge nonce store](#2-configure-the-challenge-nonce-store)*.

The authentication token validator configuration and construction is described in more detail in section *[4. Configure the authentication token validator](#4-configure-the-authentication-token-validator)*. Once the validator object has been constructed, it can be used for validating authentication tokens as follows:

```php  
$challengeNonce = (new ChallengeNonceStore())->getAndRemove()->getBase64EncodedNonce();
$token = new WebEidAuthToken($tokenString);

$tokenValidator = (new AuthTokenValidatorBuilder)
  ->withSiteOrigin(new Uri(...))
  ->withTrustedCertificateAuthorities(...)
  ->build();

$userCertificate = $tokenValidator->validate($token, $challengeNonce);
```
The `validate()` method returns the validated user certificate object if validation is successful or throws an exception as described in section *[Possible validation errors](#possible-validation-errors)* below if validation fails. The `CertificateData` class and `ucwords` function can be used for extracting user information from the user certificate object:

```php  
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateData;
...
    
CertificateData::getSubjectCN($userCertificate); // "JÕEORG\\,JAAK-KRISTJAN\\,38001085718"
CertificateData::getSubjectIdCode($userCertificate); // "PNOEE-38001085718"
CertificateData::getSubjectCountryCode($userCertificate); // "EE"

ucwords(CertificateData::getSubjectGivenName($userCertificate), "-"); // "Jaak-Kristjan"
ucwords(CertificateData::getSubjectSurname(userCertificate)); // "Jõeorg"
```

## Extended configuration

The following additional configuration options are available in `AuthTokenValidatorBuilder`:

- `withoutUserCertificateRevocationCheckWithOcsp()` – turns off user certificate revocation check with OCSP. OCSP check is enabled by default and the OCSP responder access location URL is extracted from the user certificate AIA extension unless a designated OCSP service is activated.

- `withDesignatedOcspServiceConfiguration(DesignatedOcspServiceConfiguration serviceConfiguration)` – activates the provided designated OCSP responder service configuration for user certificate revocation check with OCSP. The designated service is only used for checking the status of the certificates whose issuers are supported by the service, for other certificates the default AIA extension service access location will be used. See configuration examples in `testutil/OcspServiceMaker.php` - `getDesignatedOcspServiceConfiguration()`.

- `withOcspRequestTimeout(int $ocspRequestTimeout)` – sets both the connection and response timeout of user certificate revocation check OCSP requests. Default is 5 seconds.

- `withDisallowedCertificatePolicies(string ...$policies)` – adds the given policies to the list of disallowed user certificate policies. In order for the user certificate to be considered valid, it must not contain any policies present in this list. Contains the Estonian Mobile-ID policies by default as it must not be possible to authenticate with a Mobile-ID certificate when an eID smart card is expected.

- `withNonceDisabledOcspUrls(URI ...$urls)` – adds the given URLs to the list of OCSP responder access location URLs for which the nonce protocol extension will be disabled. Some OCSP responders don't support the nonce extension. Contains the ESTEID-2015 OCSP responder URL by default.

Extended configuration example:  

```php
$validator = new AuthTokenValidatorBuilder()
  ->withSiteOrigin("https://example.org")
  ->withTrustedCertificateAuthorities(trustedCertificateAuthorities())
  ->withoutUserCertificateRevocationCheckWithOcsp()
  ->withDisallowedCertificatePolicies(["1.2.3"])
  ->withNonceDisabledOcspUrls(new Uri("http://aia.example.org/cert"))
  ->build();
```

### Certificates' Authority Information Access (AIA) extension

Unless a designated OCSP responder service is in use, it is required that the AIA extension that contains the certificate’s OCSP responder access location is present in the user certificate. The AIA OCSP URL will be used to check the certificate revocation status with OCSP.

Note that there may be limitations to using AIA URLs as the services behind these URLs provide different security and SLA guarantees than dedicated OCSP responder services. In case you need a SLA guarantee, use a designated OCSP responder service.

## Possible validation errors

The `validate()` method of `AuthTokenValidator` returns the validated user certificate object if validation is successful or throws an exception if validation fails. All exceptions that can occur during validation derive from `AuthTokenException`, the list of available exceptions is available [here](src/exceptions/). Each exception file contains a documentation comment that describes under which conditions the exception is thrown.

## Stateful and stateless authentication

In the code examples above we use the PHP Session based authentication mechanism, where a cookie that contains the user session ID is set during successful login and session data is stored at sever side. Cookie-based authentication must be protected against cross-site request forgery (CSRF) attacks and extra measures must be taken to secure the cookies by serving them only over HTTPS and setting the _HttpOnly_, _Secure_ and _SameSite_ attributes.

A common alternative to stateful authentication is stateless authentication with JSON Web Tokens (JWT) or secure cookie sessions where the session data resides at the client side browser and is either signed or encrypted. Secure cookie sessions are described in [RFC 6896](https://datatracker.ietf.org/doc/html/rfc6896) and in the following [article about secure cookie-based Spring Security sessions](https://www.innoq.com/en/blog/cookie-based-spring-security-session/). Usage of both an anonymous session and a cache is required to store the challenge nonce and the time it was issued before the user is authenticated. The anonymous session must be used for protection against [forged login attacks](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests) by guaranteeing that the authentication token is received from the same browser to which the corresponding challenge nonce was issued. The cache must be used for protection against replay attacks by guaranteeing that each authentication token can be used exactly once.

# Challenge nonce generation

The authentication protocol requires support for generating challenge nonces, large random numbers that can be used only once, and storing them for later use during token validation. The validation library uses the random_bytes (or openssl_random_pseudo_bytes) PHP built-in function as the secure random source and the `ChallengeNonceStore` interface for storing issued challenge nonces.

The authentication protocol requires a REST endpoint that issues challenge nonces as described in section *[5. Add a REST endpoint for issuing challenge nonces](#5-add-a-rest-endpoint-for-issuing-challenge-nonces)*.

Nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

## Basic usage

As described in section *[2. Configure the nonce generator](#2-configure-the-nonce-generator)*, the are no mandatory configuration parameters for the challenge nonce generator. It uses PHP Session as default storage.

The challenge nonce store is used to save the nonce value along with the nonce expiry time. It must be possible to look up the challenge nonce data structure from the store using an identifier specific to the browser session. The values from the store are used by the token validator as described in the section *[Authentication token validation > Basic usage](#basic-usage)* that also contains recommendations for store usage and configuration.

The nonce generator configuration and construction is described in more detail in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*. Once the generator object has been constructed, it can be used for generating nonces as follows:

```php
$generator = (new ChallengeNonceGeneratorBuilder())->build();
$challengeNonce = $generator->generateAndStoreNonce();  
```

The `generateAndStoreNonce()` method both generates the nonce and saves it in the store.

## Extended configuration  

The following additional configuration options are available in `ChallengeNonceGeneratorBuilder`:

- `withNonceTtl(int $seconds)` – overrides the default challenge nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired. Default challenge nonce time-to-live is 5 minutes.
- `withSecureRandom(SecureRandom)` - allows to specify a custom `SecureRandom` instance.

Extended configuration example:

```php  
$generator = (new ChallengeNonceGeneratorBuilder())
  ->withNonceTtl(300) // 5 minutes
  ->withSecureRandom(customSecureRandom)  
  ->build();
```

# Example implementation

Take the files from the `examples` folder and change the tokenValidator site origin.

Execute the following composer commands:

```
composer install
composer dump-autoload
```

Please note, that there are no certificate files included in this example. You can find certificates from [here](https://www.skidsolutions.eu/en/repository/certs)

# Code formatting

We are using `Prettier` for code formatting. To install Prettier, use following command:

```
npm install --global prettier @prettier/plugin-php
```
Run command for code formatting:
```
composer fix-php
```

# Testing

Run phpunit in the root directory to run all unit tests.

```
./vendor/bin/phpunit tests
```
