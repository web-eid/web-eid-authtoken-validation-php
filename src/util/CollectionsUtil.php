<?php

/*
 * Copyright (c) 2022-2023 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\util;

use IteratorAggregate;
use Countable;
use ArrayIterator;
use ArrayAccess;
use phpseclib3\File\X509;
use TypeError;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateValidator;
use GuzzleHttp\Psr7\Uri;

/**
 * @copyright 2022 Petr Muzikant pmuzikant@email.cz
 */
abstract class Collection implements Countable, IteratorAggregate, ArrayAccess
{
    protected array $array;

    abstract public function __construct();
    abstract public function validateType($value): void;

    public function offsetExists(mixed $offset): bool
    {
        return isset($this->array[$offset]);
    }

    #[\ReturnTypeWillChange]
    public function offsetGet(mixed $offset): mixed
    {
        return $this->array[$offset];
    }

    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->validateType($value);
        $this->array[$offset] = $value;
    }

    public function offsetUnset(mixed $offset): void
    {
        unset($this->array[$offset]);
    }

    public function count(): int
    {
        return count($this->array);
    }

    public function getIterator(): ArrayIterator
    {
        return new ArrayIterator($this->array);
    }

    public function pushItem($value): void
    {
        $this->validateType($value);
        array_push($this->array, $value);
    }
}

class X509Collection extends Collection
{
    public function __construct(X509 ...$certificates)
    {
        $this->array = $certificates;
    }

    public function validateType($value): void
    {
        if (!$value instanceof X509) {
            throw new TypeError("Wrong type, expected " . X509::class);
        }
    }

    // For logging purpose
    public static function getSubjectDNs(?X509Collection $x509Collection, X509 ...$certificates): array
    {
        $array = is_null($x509Collection) ? $certificates : $x509Collection;
        $subjectDNs = [];
        foreach ($array as $certificate) {
            $subjectDNs[] = $certificate->getSubjectDN(X509::DN_STRING);
        }
        return $subjectDNs;
    }
}

class SubjectCertificateValidatorCollection extends Collection
{
    public function __construct(SubjectCertificateValidator ...$validators)
    {
        $this->array = $validators;
    }

    public function validateType($value): void
    {
        if (!$value instanceof SubjectCertificateValidator) {
            throw new TypeError("Wrong type, expected " . SubjectCertificateValidator::class);
        }
    }
}

class UriCollection extends Collection
{
    public function __construct(Uri ...$urls)
    {
        $this->array = $urls;
    }

    public function validateType($value): void
    {
        if (!$value instanceof Uri) {
            throw new TypeError("Wrong type, expected " . Uri::class);
        }
    }

    public function getUrls(): array
    {
        $result = [];
        foreach ($this->array as $uri) {
            $result[] = $uri;
        }
        return $result;
    }

    public function getUrlsArray(): array
    {
        $result = [];
        foreach ($this->array as $uri) {
            $result[] = $uri->jsonSerialize();
        }
        return $result;
    }
}
