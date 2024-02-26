<?php

/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
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
            $valueArr[$i] = ord(substr($result, $i));
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
