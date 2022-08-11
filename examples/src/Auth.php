<?php

use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateData;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateLoader;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceGenerator;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceGeneratorBuilder;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceStore;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
use web_eid\web_eid_authtoken_validation_php\util\Uri;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidatorBuilder;

class Auth
{

    public function trustedIntermediateCACertificates(): array
    {
        return CertificateLoader::loadCertificatesFromResources(
            __DIR__ . "/../certificates/esteid2018.der.crt", __DIR__ . "/../certificates/ESTEID-SK_2015.der.crt"
        );
    }

    public function generator(): ChallengeNonceGenerator
    {
        return (new ChallengeNonceGeneratorBuilder())
            ->withNonceTtl(300)
            ->build();
    }

    public function tokenValidator(): AuthTokenValidator
    {
        return (new AuthTokenValidatorBuilder())
            ->withSiteOrigin(new Uri('https://localhost:8443'))
            ->withTrustedCertificateAuthorities(...self::trustedIntermediateCACertificates())
            ->build();
    }

    /**
     * Get challenge nonce
     *
     * @return string
     */    
    public function getNonce()
    {
        try {
            header('Content-Type: application/json; charset=utf-8');
            $generator = $this->generator();
            $challengeNonce = $generator->generateAndStoreNonce();
            $responseArr = [];
            $responseArr["nonce"] = $challengeNonce->getBase64EncodedNonce();
            echo json_encode($responseArr);
        } catch (Exception $e) {
            header("HTTP/1.0 400 Bad Request");
            echo $e->getMessage();
        }
    }

    /**
     * Authenticate
     *
     * @return string
     */    
    public function validate()
    {
        $authToken = file_get_contents('php://input');

        try {

            /* Get and remove nonce from store */
            $challengeNonce = (new ChallengeNonceStore())->getAndRemove();

            try {

                // Build token validator
                $tokenValidator = $this->tokenValidator();

                // Validate token
                $cert = $tokenValidator->validate(new WebEidAuthToken($authToken), $challengeNonce->getBase64EncodedNonce());

                session_regenerate_id();

                $subjectName = CertificateData::getSubjectGivenName($cert) . " " . CertificateData::getSubjectSurname($cert);
                $result = [
                    'sub' => $subjectName
                ];

                $_SESSION["auth-user"] = $subjectName;

                echo json_encode($result);

            } catch (Exception $e) {
                header("HTTP/1.0 400 Bad Request");
                echo $e->getMessage();
            }

        } catch (ChallengeNonceExpiredException $e) {
            header("HTTP/1.0 400 Bad Request");
            echo $e->getMessage();
        }
    }

    /**
     * Logout
     *
     */
    public function logout()
    {
        unset($_SESSION["auth-user"]);
        session_regenerate_id();
        // Redirect to login
        header("location:/");
    }

}