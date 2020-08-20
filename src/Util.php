<?php

/**
 * This file is part of ethereum-util package.
 *
 * (c) Kuan-Cheng,Lai <alk03073135@gmail.com>
 *
 * @author Peter Lai <alk03073135@gmail.com>
 * @license MIT
 */

namespace Web3p\EthereumUtil;

use InvalidArgumentException;
use RuntimeException;
use kornrunner\Keccak;
use Elliptic\EC;
use Elliptic\EC\KeyPair;
use Elliptic\EC\Signature;
use phpseclib\Math\BigInteger as BigNumber;

class Util
{
    /**
     * SHA3_NULL_HASH
     *
     * @const string
     */
    const SHA3_NULL_HASH = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

    public static function UNITS()
    {
        return [
            'noether' => '0',
            'wei' => '1',
            'kwei' => '1000',
            'Kwei' => '1000',
            'babbage' => '1000',
            'femtoether' => '1000',
            'mwei' => '1000000',
            'Mwei' => '1000000',
            'lovelace' => '1000000',
            'picoether' => '1000000',
            'gwei' => '1000000000',
            'Gwei' => '1000000000',
            'shannon' => '1000000000',
            'nanoether' => '1000000000',
            'nano' => '1000000000',
            'szabo' => '1000000000000',
            'microether' => '1000000000000',
            'micro' => '1000000000000',
            'finney' => '1000000000000000',
            'milliether' => '1000000000000000',
            'milli' => '1000000000000000',
            'ether' => '1000000000000000000',
            'kether' => '1000000000000000000000',
            'grand' => '1000000000000000000000',
            'mether' => '1000000000000000000000000',
            'gether' => '1000000000000000000000000000',
            'tether' => '1000000000000000000000000000000'
        ];
    }

    /**
     * toHex
     * Encoding string or integer or numeric string(is not zero prefixed) or big number to hex.
     *
     * @param string|int|BigNumber $value
     * @param bool $isPrefix
     * @return string
     */
    public static function toHex($value, $isPrefix = false)
    {
        if (is_numeric($value)) {
            // turn to hex number
            $bn = self::toBn($value);
            $hex = $bn->toHex(true);
            $hex = preg_replace('/^0+(?!$)/', '', $hex);
        } elseif (is_string($value)) {
            $value = self::stripZero($value);
            $hex = implode('', unpack('H*', $value));
        } elseif ($value instanceof BigNumber) {
            $hex = $value->toHex(true);
            $hex = preg_replace('/^0+(?!$)/', '', $hex);
        } else {
            throw new InvalidArgumentException('The value to toHex function is not support.');
        }
        if ($isPrefix) {
            return '0x' . $hex;
        }
        return $hex;
    }

    /**
     * hexToBin
     *
     * @param string
     * @return string
     */
    public static function hexToBin($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The value to hexToBin function must be string.');
        }
        if (self::isZeroPrefixed($value)) {
            $count = 1;
            $value = str_replace('0x', '', $value, $count);
        }
        return pack('H*', $value);
    }

    /**
     * isZeroPrefixed
     *
     * @param string
     * @return bool
     */
    public static function isZeroPrefixed($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The value to isZeroPrefixed function must be string.');
        }
        return (strpos($value, '0x') === 0);
    }

    /**
     * stripZero
     *
     * @param string $value
     * @return string
     */
    public static function stripZero($value)
    {
        if (self::isZeroPrefixed($value)) {
            $count = 1;
            return str_replace('0x', '', $value, $count);
        }
        return $value;
    }

    /**
     * isNegative
     *
     * @param string
     * @return bool
     */
    public static function isNegative($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The value to isNegative function must be string.');
        }
        return (strpos($value, '-') === 0);
    }

    /**
     * isAddress
     *
     * @param string $value
     * @return bool
     */
    public static function isAddress($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The value to isAddress function must be string.');
        }
        if (preg_match('/^(0x|0X)?[a-f0-9A-F]{40}$/', $value) !== 1) {
            return false;
        } elseif (preg_match('/^(0x|0X)?[a-f0-9]{40}$/', $value) === 1 || preg_match('/^(0x|0X)?[A-F0-9]{40}$/', $value) === 1) {
            return true;
        }
        return self::isAddressChecksum($value);
    }

    /**
     * isAddressChecksum
     *
     * @param string $value
     * @return bool
     */
    public static function isAddressChecksum($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The value to isAddressChecksum function must be string.');
        }
        $value = self::stripZero($value);
        $hash = self::stripZero(self::sha3(mb_strtolower($value)));

        for ($i = 0; $i < 40; $i++) {
            if (
                (intval($hash[$i], 16) > 7 && mb_strtoupper($value[$i]) !== $value[$i]) ||
                (intval($hash[$i], 16) <= 7 && mb_strtolower($value[$i]) !== $value[$i])
            ) {
                return false;
            }
        }
        return true;
    }

    /**
     * toChecksumAddress
     *
     * @param string $value
     * @return string
     */
    public static function toChecksumAddress($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The value to toChecksumAddress function must be string.');
        }
        $value = self::stripZero(strtolower($value));
        $hash = self::stripZero(self::sha3($value));
        $ret = '0x';

        for ($i = 0; $i < 40; $i++) {
            if (intval($hash[$i], 16) >= 8) {
                $ret .= strtoupper($value[$i]);
            } else {
                $ret .= $value[$i];
            }
        }
        return $ret;
    }

    /**
     * isHex
     *
     * @param string $value
     * @return bool
     */
    public static function isHex($value)
    {
        return (is_string($value) && preg_match('/^(0x)?[a-f0-9]*$/', $value) === 1);
    }

    /**
     * sha3
     * keccak256
     *
     * @param string $value
     * @return string
     */
    public static function sha3($value)
    {
        $hash = Keccak::hash(self::toString($value), 256);

        if ($hash === self::SHA3_NULL_HASH) {
            return null;
        }
        return $hash;
    }

    /**
     * @param string $value
     * @return string|null
     * @throws \Exception
     */
    public static function keccak256($value)
    {
        return self::sha3($value);
    }

    /**
     * toString
     *
     * @param mixed $value
     * @return string
     */
    public static function toString($value)
    {
        $value = (string)$value;

        return $value;
    }

    /**
     * toWei
     * Change number from unit to wei.
     * For example:
     * $wei = Utils::toWei('1', 'kwei');
     * $wei->toString(); // 1000
     *
     * @param BigNumber|string $number
     * @param string $unit
     * @return \phpseclib\Math\BigInteger
     */
    public static function toWei($number, $unit)
    {
        if (!is_string($number) && !($number instanceof BigNumber)) {
            throw new InvalidArgumentException('toWei number must be string or bignumber.');
        }
        $bn = self::toBn($number);

        if (!is_string($unit)) {
            throw new InvalidArgumentException('toWei unit must be string.');
        }
        if (!isset(self::UNITS()[$unit])) {
            throw new InvalidArgumentException('toWei doesn\'t support ' . $unit . ' unit.');
        }
        $bnt = new BigNumber(self::UNITS()[$unit]);

        if (is_array($bn)) {
            // fraction number
            list($whole, $fraction, $fractionLength, $negative1) = $bn;

            if ($fractionLength > strlen(self::UNITS()[$unit])) {
                throw new InvalidArgumentException('toWei fraction part is out of limit.');
            }
            $whole = $whole->multiply($bnt);

            // There is no pow function in phpseclib 2.0, only can see in dev-master
            // Maybe implement own biginteger in the future
            // See 2.0 BigInteger: https://github.com/phpseclib/phpseclib/blob/2.0/phpseclib/Math/BigInteger.php
            // See dev-master BigInteger: https://github.com/phpseclib/phpseclib/blob/master/phpseclib/Math/BigInteger.php#L700
            // $base = (new BigNumber(10))->pow(new BigNumber($fractionLength));

            // So we switch phpseclib special global param, change in the future
            switch (MATH_BIGINTEGER_MODE) {
                case $whole::MODE_GMP:
                    static $two;
                    $powerBase = gmp_pow(gmp_init(10), (int)$fractionLength);
                    break;
                case $whole::MODE_BCMATH:
                    $powerBase = bcpow('10', (string)$fractionLength, 0);
                    break;
                default:
                    $powerBase = pow(10, (int)$fractionLength);
                    break;
            }
            $base = new BigNumber($powerBase);
            $fraction = $fraction->multiply($bnt)->divide($base)[0];

            if ($negative1 !== false) {
                return $whole->add($fraction)->multiply($negative1);
            }
            return $whole->add($fraction);
        }

        return $bn->multiply($bnt);
    }

    /**
     * toEther
     * Change number from unit to ether.
     * For example:
     * list($bnq, $bnr) = Utils::toEther('1', 'kether');
     * $bnq->toString(); // 1000
     *
     * @param BigNumber|string|int $number
     * @param string $unit
     * @return array
     */
    public static function toEther($number, $unit)
    {
        // if ($unit === 'ether') {
        //     throw new InvalidArgumentException('Please use another unit.');
        // }
        $wei = self::toWei($number, $unit);
        $bnt = new BigNumber(self::UNITS()['ether']);

        return $wei->divide($bnt);
    }

    /**
     * fromWei
     * Change number from wei to unit.
     * For example:
     * list($bnq, $bnr) = Utils::fromWei('1000', 'kwei');
     * $bnq->toString(); // 1
     *
     * @param BigNumber|string|int $number
     * @param string $unit
     * @return \phpseclib\Math\BigInteger
     */
    public static function fromWei($number, $unit)
    {
        $bn = self::toBn($number);

        if (!is_string($unit)) {
            throw new InvalidArgumentException('fromWei unit must be string.');
        }
        if (!isset(self::UNITS()[$unit])) {
            throw new InvalidArgumentException('fromWei doesn\'t support ' . $unit . ' unit.');
        }
        $bnt = new BigNumber(self::UNITS()[$unit]);

        return $bn->divide($bnt);
    }

    /**
     * toBn
     * Change number or number string to bignumber.
     *
     * @param BigNumber|string|int $number
     * @return array|\phpseclib\Math\BigInteger
     */
    public static function toBn($number)
    {
        if ($number instanceof BigNumber) {
            $bn = $number;
        } elseif (is_int($number)) {
            $bn = new BigNumber($number);
        } elseif (is_numeric($number)) {
            $number = (string)$number;

            if (self::isNegative($number)) {
                $count = 1;
                $number = str_replace('-', '', $number, $count);
                $negative1 = new BigNumber(-1);
            }
            if (strpos($number, '.') > 0) {
                $comps = explode('.', $number);

                if (count($comps) > 2) {
                    throw new InvalidArgumentException('toBn number must be a valid number.');
                }
                $whole = $comps[0];
                $fraction = $comps[1];

                return [
                    new BigNumber($whole),
                    new BigNumber($fraction),
                    strlen($comps[1]),
                    isset($negative1) ? $negative1 : false
                ];
            } else {
                $bn = new BigNumber($number);
            }
            if (isset($negative1)) {
                $bn = $bn->multiply($negative1);
            }
        } elseif (is_string($number)) {
            $number = mb_strtolower($number);

            if (self::isNegative($number)) {
                $count = 1;
                $number = str_replace('-', '', $number, $count);
                $negative1 = new BigNumber(-1);
            }
            if (self::isZeroPrefixed($number) || preg_match('/[a-f]+/', $number) === 1) {
                $number = self::stripZero($number);
                $bn = new BigNumber($number, 16);
            } elseif (empty($number)) {
                $bn = new BigNumber(0);
            } else {
                throw new InvalidArgumentException('toBn number must be valid hex string.');
            }
            if (isset($negative1)) {
                $bn = $bn->multiply($negative1);
            }
        } else {
            throw new InvalidArgumentException('toBn number must be BigNumber, string or int.');
        }
        return $bn;
    }

    /**
     * publicKeyToAddress
     *
     * @param string $publicKey
     * @return string
     */
    public static function publicKeyToAddress($publicKey)
    {
        if (!is_string($publicKey)) {
            throw new InvalidArgumentException('The publicKey to publicKeyToAddress function must be string.');
        }
        if (self::isHex($publicKey) === false) {
            throw new InvalidArgumentException('Invalid public key format.');
        }
        $publicKey = self::stripZero($publicKey);

        if (strlen($publicKey) !== 130) {
            throw new InvalidArgumentException('Invalid public key length.');
        }
        return '0x' . substr(self::sha3(substr(hex2bin($publicKey), 1)), 24);
    }

    /**
     * privateKeyToPublicKey
     *
     * @param string $privateKey
     * @return string
     */
    public static function privateKeyToPublicKey($privateKey)
    {
        if (!is_string($privateKey)) {
            throw new InvalidArgumentException('The privateKey to privateKeyToPublicKey function must be string.');
        }
        if (self::isHex($privateKey) === false) {
            throw new InvalidArgumentException('Invalid private key format.');
        }
        $privateKey = self::stripZero($privateKey);

        if (strlen($privateKey) !== 64) {
            throw new InvalidArgumentException('Invalid private key length.');
        }
        $privateKey = (new EC('secp256k1'))->keyFromPrivate($privateKey, 'hex');
        $publicKey = $privateKey->getPublic(false, 'hex');

        return '0x' . $publicKey;
    }

    /**
     * recoverPublicKey
     *
     * @param string $hash
     * @param string $r
     * @param string $s
     * @param int $v
     * @return string
     */
    public static function recoverPublicKey($hash, $r, $s, $v)
    {
        if (!is_string($hash)) {
            throw new InvalidArgumentException('The hash to recoverPublicKey function must be string.');
        }
        if (!is_string($r)) {
            throw new InvalidArgumentException('The r to recoverPublicKey function must be string.');
        }
        if (!is_string($s)) {
            throw new InvalidArgumentException('The s to recoverPublicKey function must be string.');
        }
        if (!is_int($v)) {
            throw new InvalidArgumentException('The hash to recoverPublicKey function must be int.');
        }
        if (self::isHex($hash) === false) {
            throw new InvalidArgumentException('Invalid hash format.');
        }
        $hash = self::stripZero($hash);

        if (self::isHex($r) === false || self::isHex($s) === false) {
            throw new InvalidArgumentException('Invalid signature format.');
        }
        $r = self::stripZero($r);
        $s = self::stripZero($s);

        if (strlen($r) !== 64 || strlen($s) !== 64) {
            throw new InvalidArgumentException('Invalid signature length.');
        }
        $publicKey = (new EC('secp256k1'))->recoverPubKey($hash, [
            'r' => $r,
            's' => $s
        ], $v);
        $publicKey = $publicKey->encode('hex');

        return '0x' . $publicKey;
    }

    /**
     * ecsign
     *
     * @param string $privateKey
     * @param string $message
     * @return \Elliptic\EC\Signature
     */
    public static function ecsign($privateKey, $message)
    {
        if (!is_string($privateKey)) {
            throw new InvalidArgumentException('The privateKey to ecsign function must be string.');
        }
        if (!is_string($message)) {
            throw new InvalidArgumentException('The message to ecsign function must be string.');
        }
        if (self::isHex($privateKey) === false) {
            throw new InvalidArgumentException('Invalid private key format.');
        }
        $privateKeyLength = strlen(self::stripZero($privateKey));

        if ($privateKeyLength % 2 !== 0 && $privateKeyLength !== 64) {
            throw new InvalidArgumentException('Private key length was wrong.');
        }
        $secp256k1 = new EC('secp256k1');
        $privateKey = $secp256k1->keyFromPrivate($privateKey, 'hex');
        $signature = $privateKey->sign($message, [
            'canonical' => true
        ]);
        // Ethereum v is recovery param + 35
        // Or recovery param + 35 + (chain id * 2)
        $signature->recoveryParam += 35;

        return $signature;
    }

    /**
     * hasPersonalMessage
     *
     * @param string $message
     * @return string
     */
    public static function hashPersonalMessage($message)
    {
        if (!is_string($message)) {
            throw new InvalidArgumentException('The message to hashPersonalMessage function must be string.');
        }
        $prefix = sprintf("\x19Ethereum Signed Message:\n%d", mb_strlen($message));
        return self::sha3($prefix . $message);
    }
}