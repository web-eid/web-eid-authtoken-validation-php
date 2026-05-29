<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\util\SubjectCertificateValidatorCollection;

class SubjectCertificateValidatorBatch
{
    private SubjectCertificateValidatorCollection $validatorList;

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public function __construct(SubjectCertificateValidator ...$validatorList)
    {
        $this->validatorList = new SubjectCertificateValidatorCollection(...$validatorList);
    }

    public function executeFor(X509 $subjectCertificate): void
    {
        foreach ($this->validatorList as $validator) {
            $validator->validate($subjectCertificate);
        }
    }

    public function addOptional(bool $condition, SubjectCertificateValidator $optionalValidator): SubjectCertificateValidatorBatch
    {
        if ($condition) {
            $this->validatorList->pushItem($optionalValidator);
        }

        return $this;
    }
}
