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

class Config
{
    private $configArr;
    private Logger $logger;

    public static function fromArray($configArr)
    {
        $instance = new self();
        $instance->configArr = $configArr;
        $instance->logger = new Logger();
        return $instance;
    }

    public function overrideFromEnv()
    {
        foreach ($this->configArr as $key => $value) {
            $envKey = 'WEB_EID_SAMPLE_'.strtoupper($key);
            $envValue = getenv($envKey);
            if ($envValue !== false) {
                $this->configArr[$key] = $envValue;
            }
        }

        return $this;
    }

    public function get($name)
    {
        return isset ($this->configArr[$name]) ? $this->configArr[$name] : null;
    }

    public function allowHttpOnLocalhost()
    {
        $localOrigin = $this->get('origin_url');
        if (str_ends_with($localOrigin, '/')) {
            throw new InvalidArgumentException("Configuration parameter origin_url cannot end with '/': " . $localOrigin);
        }

        if (str_starts_with($localOrigin, 'http:')) {

            $parsedUrl = parse_url($localOrigin);
            if (!$parsedUrl || !isset($parsedUrl['host'])) {
                throw new InvalidArgumentException("Configuration parameter origin_url does not contain an URL: " . $localOrigin);
            }

            if ($this->isLoopbackAddress($parsedUrl['host'])) {
                $this->configArr['origin_url'] = preg_replace('/^http:/', 'https:', $localOrigin);
                $this->configArr['session_name'] = preg_replace('/^__Host-/', '', $this->get('session_name'));
                $this->logger->warning("Configuration origin_url contains http protocol $localOrigin, which is not supported. Replacing it with secure " . $this->get('origin_url'));
            }

        }

        return $this;
    }

    public function isLoopbackAddress($hostname): bool
    {
        if (strtolower($hostname) === 'localhost') {
            return true;
        }

        $hostname = trim($hostname, '[]');

        // Validate if it's a valid IP address
        if (filter_var($hostname, FILTER_VALIDATE_IP)) {
            return filter_var($hostname, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
        }

        return false;
    }
}
