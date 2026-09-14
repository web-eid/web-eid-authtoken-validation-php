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

use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenException;
use phpseclib3\File\X509;

interface AuthTokenVersionValidator
{
    /**
     * Returns whether this validator supports validation of the given token format.
     *
     * @param string|null $format the format string from the Web eID authentication token
     *        (e.g. "web-eid:1.0", "web-eid:1.1")
     * @return true if this validator can handle the given format, false otherwise
     */
    public function supports(?string $format): bool;

    /**
     * Validates the Web eID authentication token signed by the subject and returns
     * the subject certificate that can be used for retrieving information about the subject.
     * <p>
     * See {@link CertificateData} and {@link Strings} for convenience methods for retrieving user
     * information from the certificate.
     *
     * @param WebEidAuthToken $authToken the Web eID authentication token
     * @param string $currentChallengeNonce the challenge nonce that is associated with the authentication token
     * @return X509 subject certificate
     * @throws AuthTokenException when validation fails
     */
    public function validate(WebEidAuthToken $authToken, string $currentChallengeNonce): X509;
}
