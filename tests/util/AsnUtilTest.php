<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\util;

use PHPUnit\Framework\TestCase;

class AsnUtilTest extends TestCase
{
    public function testTranscodeSignatureToDer(): void
    {
        $signature = "7V8AcyP23QWuVZAOSJuZ2cLLn3l41VgTmQ4q9GTjV8ENkFKAXtwVk8cTvfVODl3ZU4xEA9CvF6xJ8ysBdAew8Q";
        $decodedSignature = base64_decode($signature);
        $result = AsnUtil::transcodeSignatureToDER($decodedSignature);
        $valueArr = [];
        for ($i = 0; $i < strlen($result); $i++) {
            $valueArr[$i] = ord($result[$i]);
        }
        // First byte value
        $this->assertEquals($valueArr[0], 48);
        // Length
        $this->assertEquals($valueArr[1], count($valueArr) - 2);
        // Third byte value must be 2
        $this->assertEquals($valueArr[2], 2);
        // Next byte value 2 positon
        $separator = $valueArr[$valueArr[3] + 4];
        $this->assertEquals($separator, 2);
        
        $this->assertEquals($valueArr[$separator + 1], count($valueArr) - $valueArr[3] - 5);
    }
}
