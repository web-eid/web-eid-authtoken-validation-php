<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator;

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;

/**
 * Parses and validates the provided Web eID authentication token.
 */
interface AuthTokenValidator
{
    public const CURRENT_TOKEN_FORMAT_VERSION = 'web-eid:1';

    /**
     * Parses the Web eID authentication token signed by the subject.
     *
     * @param String $authToken the Web eID authentication token string, in Web eID JSON format
     * @return the Web eID authentication token
     */
    public function parse(string $authToken): WebEidAuthToken;

    /**
     * Validates the Web eID authentication token signed by the subject and returns
     * the subject certificate that can be used for retrieving information about the subject.
     * <p>
     * See {@link CertificateData} and {@link TitleCase} for convenience methods for retrieving user
     * information from the certificate.
     *
     * @param WebEidAuthToken authToken the Web eID authentication token
     * @param String currentChallengeNonce the challenge nonce that is associated with the authentication token
     * @return validated subject certificate
     */
    public function validate(WebEidAuthToken $authToken, string $currentChallengeNonce): X509;
}
