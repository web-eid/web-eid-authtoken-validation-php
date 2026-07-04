<?php

/*
 * Copyright (c) 2022-2026 Estonian Information System Authority
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

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use BadFunctionCallException;
use DateTime;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotYetValidException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
use web_eid\web_eid_authtoken_validation_php\util\DefaultClock;

final class CertificateValidator
{
    /**
     * Maximum number of certificates in a certification path, including the leaf
     * and excluding the trust anchor.
     */
    private const MAX_PATH_LENGTH = 8;

    public function __construct()
    {
        throw new BadFunctionCallException("Utility class");
    }

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public static function certificateIsValidOnDate(X509 $subjectCertificate, DateTime $date, string $subject): void
    {
        if (!$subjectCertificate->validateDate($date)) {
            $validity = $subjectCertificate->getCurrentCert()['tbsCertificate']['validity'];

            $notBefore = new DateTime($validity['notBefore']['utcTime'] ?? $validity['notBefore']['generalTime']);
            $notAfter = new DateTime($validity['notAfter']['utcTime'] ?? $validity['notAfter']['generalTime']);

            if ($date < $notBefore) {
                throw new CertificateNotYetValidException($subject);
            }

            if ($date > $notAfter) {
                throw new CertificateExpiredException($subject);
            }
        }
    }

    /**
     * Validates that the certificate is currently valid and chains to a configured trusted CA,
     * optionally using token-supplied intermediate CA certificates as untrusted path-building
     * candidates. The built path must always terminate at a configured trust anchor.
     *
     * When an intermediate revocation checker is given, every non-anchor intermediate
     * certificate of the built path is checked for revocation; an intermediate that is
     * revoked or whose status cannot be established fails the validation.
     *
     * @param string $certificateSubject leaf certificate role label used in validity error
     *        messages, e.g. "User", "Signing" or "AIA OCSP responder"
     * @param X509[] $additionalIntermediateCertificates untrusted candidate certificates
     * @return X509 the certificate that directly issued the given certificate;
     *         the trust anchor when the anchor is the direct issuer
     *
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public static function validateIsValidAndSignedByTrustedCA(
        X509 $certificate,
        TrustedCertificates $trustedCertificates,
        string $certificateSubject = "User",
        array $additionalIntermediateCertificates = [],
        ?IntermediateRevocationChecker $intermediateRevocationChecker = null,
        ?DateTime $now = null,
    ): X509 {
        $now = $now ?? DefaultClock::getInstance()->now();
        self::certificateIsValidOnDate($certificate, $now, $certificateSubject);

        // Prevent SSRF via CA Issuers URI from user-provided certificate AIA.
        // All CA certificates must come from configuration or from the token itself.
        X509::disableURLFetch();

        [$path, $trustAnchor] = self::buildCertificationPath(
            $certificate,
            $trustedCertificates,
            $additionalIntermediateCertificates,
            $now,
        );

        if ($intermediateRevocationChecker !== null) {
            self::validateIntermediateCertificatesNotRevoked(
                $path,
                $trustAnchor,
                $additionalIntermediateCertificates,
                $intermediateRevocationChecker,
            );
        }

        // Verify that the trust anchor is presently valid; it is not covered by the checks above.
        self::certificateIsValidOnDate($trustAnchor, $now, "Trusted CA");

        // The path is ordered from the subject towards the anchor and excludes the anchor,
        // so index 1 (when present) is the subject's direct issuer; otherwise the subject
        // was issued directly by the trust anchor.
        return count($path) > 1 ? $path[1] : $trustAnchor;
    }

    public static function buildTrustFromCertificates(array $certificates): TrustedCertificates
    {
        return new TrustedCertificates($certificates);
    }

    /**
     * Builds a certification path from the given certificate to a configured trust anchor,
     * verifying the signature of every link. Token-supplied intermediates are candidates
     * only; a path that does not terminate at a trust anchor is rejected.
     *
     * @param X509[] $additionalIntermediateCertificates
     * @return array{0: X509[], 1: X509} the path ordered from the subject towards the anchor,
     *         excluding the anchor, and the trust anchor itself
     */
    private static function buildCertificationPath(
        X509 $certificate,
        TrustedCertificates $trustedCertificates,
        array $additionalIntermediateCertificates,
        DateTime $now,
    ): array {
        $path = [$certificate];
        $result = self::findCertificationPath(
            $certificate,
            $trustedCertificates,
            $additionalIntermediateCertificates,
            $path,
            $now,
        );
        if ($result !== null) {
            return $result;
        }

        throw new CertificateNotTrustedException($certificate);
    }

    /**
     * @param X509[] $candidates
     * @param X509[] $path
     */
    private static function findCertificationPath(
        X509 $current,
        TrustedCertificates $trustedCertificates,
        array $candidates,
        array $path,
        DateTime $now,
    ): ?array {
        if (count($path) > self::MAX_PATH_LENGTH) {
            return null;
        }

        // Prefer terminating the path at a configured trust anchor.
        foreach ($trustedCertificates->getCertificates() as $trustedCertificate) {
            if (self::isSignedBy($current, $trustedCertificate)) {
                return [$path, $trustedCertificate];
            }
        }

        foreach ($candidates as $candidate) {
            // Loop protection: a certificate must not appear in the path twice.
            foreach ($path as $pathCertificate) {
                if ($candidate->getCurrentCert() == $pathCertificate->getCurrentCert()) {
                    continue 2;
                }
            }
            // An expired or not yet valid CA certificate cannot be part of a valid path.
            if (!$candidate->validateDate($now)) {
                continue;
            }
            if (!self::isCertificateAuthority($candidate)) {
                continue;
            }
            if (self::isSignedBy($current, $candidate)) {
                $result = self::findCertificationPath(
                    $candidate,
                    $trustedCertificates,
                    $candidates,
                    [...$path, $candidate],
                    $now,
                );
                if ($result !== null) {
                    return $result;
                }
            }
        }
        return null;
    }

    /**
     * Returns whether a token-supplied issuer candidate is permitted to issue certificates.
     * A CA certificate must assert basicConstraints cA=true and, when keyUsage is present,
     * it must permit certificate signing.
     */
    private static function isCertificateAuthority(X509 $certificate): bool
    {
        $basicConstraints = $certificate->getExtension("id-ce-basicConstraints");
        if (!is_array($basicConstraints) || ($basicConstraints["cA"] ?? false) !== true) {
            return false;
        }

        $keyUsage = $certificate->getExtension("id-ce-keyUsage");
        return $keyUsage === false ||
            (is_array($keyUsage) && in_array("keyCertSign", $keyUsage, true));
    }

    /**
     * Verifies a single certification path link: the issuer candidate's subject must match
     * the certificate's issuer and the certificate's signature must verify against the
     * candidate's public key.
     *
     * The verifier is cloned from the original certificate because phpseclib verifies the
     * signature against the certificate bytes captured at load time; re-encoding a
     * certificate is not guaranteed to be byte-identical. Cloning also isolates the CA
     * certificates loaded for each candidate path.
     */
    private static function isSignedBy(X509 $certificate, X509 $issuerCandidate): bool
    {
        try {
            // Avoid accumulating issuer candidates on the source certificate while
            // alternative certification paths are explored.
            $verifier = clone $certificate;
            $issuerCandidatePem = $issuerCandidate->saveX509($issuerCandidate->getCurrentCert(), X509::FORMAT_PEM);
            if (!$verifier->loadCA($issuerCandidatePem)) {
                return false;
            }
            return $verifier->validateSignature() === true;
        } catch (\Throwable $e) {
            // An unsupported signature algorithm or malformed candidate cannot verify the link.
            return false;
        }
    }

    /**
     * Checks the revocation status of the non-anchor intermediate certificates of the built
     * path, i.e. everything except the leaf, whose revocation policy is role-specific and
     * applied by the caller, and the trust anchor, which is not part of the built path.
     *
     * @param X509[] $path
     * @param X509[] $additionalIntermediateCertificates
     */
    private static function validateIntermediateCertificatesNotRevoked(
        array $path,
        X509 $trustAnchor,
        array $additionalIntermediateCertificates,
        IntermediateRevocationChecker $intermediateRevocationChecker,
    ): void {
        for ($i = 1; $i < count($path); $i++) {
            $issuer = $path[$i + 1] ?? $trustAnchor;
            try {
                $intermediateRevocationChecker->validateNotRevoked(
                    $path[$i],
                    $issuer,
                    $additionalIntermediateCertificates,
                );
            } catch (AuthTokenException $e) {
                throw new CertificateNotTrustedException($path[$i], $e);
            }
        }
    }
}
