<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp\exceptions;

use Exception;

/**
 * Base class for all OCSP exceptions.
 */
abstract class OcspException extends Exception
{
    /**
     * @param string $message — [optional] The Exception message to throw
     */
    public function __construct($message)
    {
        parent::__construct($message);
    }
}
