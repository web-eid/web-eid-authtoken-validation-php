<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\util;

use Countable;

final class TrustedCertificates implements Countable
{
    private X509Collection $certificates;

    public function __construct(array $certificates)
    {
        $this->certificates = new X509Collection(...$certificates);
    }

    public function count(): int
    {
        return count($this->certificates);
    }

    public function getCertificates(): X509Collection
    {
        return $this->certificates;
    }
}
