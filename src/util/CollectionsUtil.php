<?php

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\util;

use IteratorAggregate;
use Countable;
use ArrayIterator;
use ArrayAccess;
use phpseclib3\File\X509;
use TypeError;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateValidator;

abstract class Collection implements Countable, IteratorAggregate, ArrayAccess
{
    protected array $array;

    abstract public function __construct();
    abstract public function validate($value): void;

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
        $this->validate($value);
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
        $this->validate($value);
        array_push($this->array, $value);
    }
}

class X509Collection extends Collection
{
    public function __construct(X509 ...$certificates)
    {
        $this->array = $certificates;
    }

    public function validate($value): void
    {
        if (!$value instanceof X509) {
            throw new TypeError("Wrong type, expected " . X509::class);
        }
    }

    // For logging purpose
    public static function getSubjectDNs(?X509Collection $x509Collection, X509 ...$certificates): array
    {
        $array = is_null($x509Collection) ? $certificates : $x509Collection;
        $subjectDNs = array();
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

    public function validate($value): void
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

    public function validate($value): void
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
            $result[] = $uri->getUrl();
        }
        return $result;
    }
}
