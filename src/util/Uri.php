<?php

/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\util;

use web_eid\web_eid_authtoken_validation_php\exceptions\MalformedUriException;

use InvalidArgumentException;

use function PHPUnit\Framework\isNull;

class Uri
{

    private $scheme = '';
    private $user = '';
    private $password = '';
    private $host = '';
    private $port;
    private $path = '';
    private $query = '';
    private $fragment = '';

    /**
     * Unreserved characters for use in a regex.
     *
     * @link https://tools.ietf.org/html/rfc3986#section-2.3
     */
    private const CHAR_UNRESERVED = 'a-zA-Z0-9_\-\.~';
    
    /**
     * Sub-delims for use in a regex.
     *
     * @link https://tools.ietf.org/html/rfc3986#section-2.2
     */
    private const CHAR_SUB_DELIMS = '!\$&\'\(\)\*\+,;=';    


    public function __construct(string $uri = '')
    {
        if ($uri !== '') {            
            $parts = self::parse($uri);
            if ($parts === false) {
                throw new MalformedUriException($uri);
            }
            $this->setParts($parts);
        }
    }

    public function getScheme(): string
    {
        return $this->scheme;
    }

    public function getUser(): string
    {
        return $this->user;
    }    

    public function getPassword(): string
    {
        return $this->password;
    }    

    public function getHost(): string
    {
        return $this->host;
    }

    public function getPort(): ?int
    {
        return $this->port;
    }

    public function getQuery(): string
    {
        return $this->query;
    }

    public function getFragment(): string
    {
        return $this->fragment;
    }

    public function getPath(): string
    {
        return $this->path;
    }

    /**
     * UTF-8 aware \parse_url() replacement.
     *
     * The internal function produces broken output for non ASCII domain names
     * (IDN) when used with locales other than "C".
     *
     * On the other hand, cURL understands IDN correctly only when UTF-8 locale
     * is configured ("C.UTF-8", "en_US.UTF-8", etc.).
     *
     * @see https://bugs.php.net/bug.php?id=52923
     * @see https://www.php.net/manual/en/function.parse-url.php#114817
     * @see https://curl.haxx.se/libcurl/c/CURLOPT_URL.html#ENCODING
     *
     * @return array|false
     */    
    private static function parse(string $url)
    {
        // If IPv6
        $prefix = '';
        if (preg_match('%^(.*://\[[0-9:a-f]+\])(.*?)$%', $url, $matches)) {
            /** @var array{0:string, 1:string, 2:string} $matches */
            $prefix = $matches[1];
            $url = $matches[2];
        }

        /** @var string */
        $encodedUrl = preg_replace_callback(
            '%[^:/@?&=#]+%usD',
            static function ($matches) {
                return urlencode($matches[0]);
            },
            $url
        );

        $result = parse_url($prefix . $encodedUrl);

        if ($result === false) {
            return false;
        }

        return array_map('urldecode', $result);        

    }

    /**
     * Sets parse_url parts to a URI.
     *
     * @param array $parts Array of parse_url parts to apply.
     */    
    private function setParts(array $parts): void
    {
        $this->scheme = isset($parts['scheme']) ? $this->filterScheme($parts['scheme']) : '';
        $this->host = isset($parts['host']) ? $this->filterHost($parts['host']) : '';
        $this->port = isset($parts['port']) ? $this->filterPort($parts['port']) : null;
        $this->path = isset($parts['path']) ? $this->filterPath($parts['path']) : '';
        $this->query = isset($parts['query']) ? $this->filterQueryAndFragment($parts['query']) : '';
        $this->fragment = isset($parts['fragment']) ? $this->filterQueryAndFragment($parts['fragment']) : '';
        $this->user = isset($parts['user']) ? $this->filterUser($parts['user']) : '';
        $this->password = isset($parts['pass']) ? $parts['pass'] : '';
    }

    /**
     * @param mixed $scheme
     *
     * @throws InvalidArgumentException If the scheme is invalid.
     */
    private function filterScheme($scheme): string
    {
        if (!is_string($scheme)) {
            throw new InvalidArgumentException('Scheme must be a string');
        }
        return \strtr($scheme, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
    }

    /**
     * @param mixed $component
     *
     * @throws InvalidArgumentException If the user info is invalid.
     */
    private function filterUser($component): string
    {
        if (!is_string($component)) {
            throw new InvalidArgumentException('User must be a string');
        }

        return preg_replace_callback(
            '/(?:[^%' . self::CHAR_UNRESERVED . self::CHAR_SUB_DELIMS . ']+|%(?![A-Fa-f0-9]{2}))/',
            [$this, 'rawurlencodeMatchZero'],
            $component
        );
    }    

    /**
     * @param mixed $host
     *
     * @throws InvalidArgumentException If the host is invalid.
     */
    private function filterHost($host): string
    {
        if (!is_string($host)) {
            throw new InvalidArgumentException('Host must be a string');
        }

        return \strtr($host, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
    }
    
    /**
     * @param mixed $port
     *
     * @throws \InvalidArgumentException If the port is invalid.
     */
    private function filterPort($port): ?int
    {
        if ($port === null) {
            return null;
        }

        $port = (int) $port;
        if (0 > $port || 0xffff < $port) {
            throw new InvalidArgumentException(
                sprintf('Invalid port: %d. Must be between 0 and 65535', $port)
            );
        }

        return $port;
    }

    /**
     * Filters the path of a URI
     *
     * @param mixed $path
     *
     * @throws InvalidArgumentException If the path is invalid.
     */
    private function filterPath($path): string
    {
        if (!is_string($path)) {
            throw new InvalidArgumentException('Path must be a string');
        }

        return preg_replace_callback(
            '/(?:[^' . self::CHAR_UNRESERVED . self::CHAR_SUB_DELIMS . '%:@\/]++|%(?![A-Fa-f0-9]{2}))/',
            [$this, 'rawurlencodeMatchZero'],
            $path
        );
    }

    /**
     * Filters the query string or fragment of a URI.
     *
     * @param mixed $str
     *
     * @throws InvalidArgumentException If the query or fragment is invalid.
     */
    private function filterQueryAndFragment($str): string
    {
        if (!is_string($str)) {
            throw new InvalidArgumentException('Query and fragment must be a string');
        }

        return preg_replace_callback(
            '/(?:[^' . self::CHAR_UNRESERVED . self::CHAR_SUB_DELIMS . '%:@\/\?]++|%(?![A-Fa-f0-9]{2}))/',
            [$this, 'rawurlencodeMatchZero'],
            $str
        );
    }    

    private function rawurlencodeMatchZero(array $match): string
    {
        return rawurlencode($match[0]);
    }

    private function getUrl(): string
    {
        $scheme   = ($this->getScheme() !== "") ? $this->getScheme() . '://' : '';
        $host     = ($this->getHost() !== "") ? $this->getHost() : '';
        $port     = !isNull($this->getPort()) ? ':' . $this->getPort() : '';
        $user     = ($this->getUser() !== "") ? $this->getUser() : '';
        $pass     = ($this->getPassword() !== "") ? ':' . $this->getPassword()  : '';
        $pass     = ($user || $pass) ? "$pass@" : '';
        $path     = ($this->getPath() !== "") ? $this->getPath() : '';
        $query    = ($this->getQuery() !== "") ? '?' . $this->getQuery() : '';
        $fragment = ($this->getFragment() !== "") ? '#' . $this->getFragment() : '';
        return "$scheme$user$pass$host$port$path$query$fragment";        
    }

    /**
     * Determine if url or path is absolute
     *
     * @param string $url
     *
     * @return bool
     */
    public function isAbsolute(): bool
    {
        $url = $this->getUrl();
        $pattern = "/^(?:ftp|https?|feed):\/\/(?:(?:(?:[\w\.\-\+!$&'\(\)*\+,;=]|%[0-9a-f]{2})+:)*
        (?:[\w\.\-\+%!$&'\(\)*\+,;=]|%[0-9a-f]{2})+@)?(?:
        (?:[a-z0-9\-\.]|%[0-9a-f]{2})+|(?:\[(?:[0-9a-f]{0,4}:)*(?:[0-9a-f]{0,4})\]))(?::[0-9]+)?(?:[\/|\?]
        (?:[\w#!:\.\?\+=&@$'~*,;\/\(\)\[\]\-]|%[0-9a-f]{2})*)?$/xi";
        return (bool) preg_match($pattern, $url);
    } 

    public function verifyComponents(array $components): bool
    {
        if ((isset($components['scheme'])) && ($this->getScheme() != $components['scheme'])) {
            return false;
        }
        if ((isset($components['host'])) && ($this->getHost() != $components['host'])) {
            return false;
        }
        if ((isset($components['port'])) && ($this->getPort() != $components['port'])) {
            return false;
        }
        return true;
    } 

}