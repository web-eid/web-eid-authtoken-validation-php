<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

class Config
{
    private $configArr;

    public static function fromArray($configArr)
    {
        $instance = new self();
        $instance->configArr = $configArr;
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
}