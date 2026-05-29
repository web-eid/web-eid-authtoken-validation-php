<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

class ChallengeNullOrEmptyException extends AuthTokenException
{

    public function __construct()
    {
        parent::__construct("Provided challenge is null or empty");
    }
}
