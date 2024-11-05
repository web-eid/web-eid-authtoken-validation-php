<?php

namespace web_eid\web_eid_authtoken_validation_php\util;

enum HashAlgorithm: string
{
    case SHA1 = "sha1";
    case SHA256 = "sha256";
    case SHA384 = "sha384";
    case SHA512 = "sha512";
    case SHA224 = "sha224";
    case SHA512_224 = "sha512/224";
    case SHA512_256 = "sha512/256";
    case MGF1 = "mgf1";
}