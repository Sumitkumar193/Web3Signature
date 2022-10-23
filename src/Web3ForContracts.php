<?php

namespace Desnake\Web3signature;

use kornrunner\Keccak;
use Illuminate\Support\Str;
use Desnake\Web3signature\Signature;

trait Web3ForContracts
{
    /**
     * @method Returns the address extracted from signature
     * @param string $msg - Message that is signed 
     * @param string $signed - Signature string with signed message
     */
    public function recoverAddress($msg, $signed)
    {
        $personal_prefix_msg = "\x19Ethereum Signed Message:\n" . strlen($msg) . $msg;
        $hex = $this->keccak256($personal_prefix_msg);
        return $this->_recoverAddress($hex, $signed);
    }

    /**
     * @method extracts r, s, and v values from signed message
     * @return string address from the signed message
     */
    public function _recoverAddress($hex, $signed)
    {
        $rHex   = substr($signed, 2, 64);
        $sHex   = substr($signed, 66, 64);
        $vValue = hexdec(substr($signed, 130, 2));
        $messageHex       = substr($hex, 2);
        $messageByteArray = unpack('C*', hex2bin($messageHex));
        $messageGmp       = gmp_init("0x" . $messageHex);
        $r = $rHex;        //hex string without 0x
        $s = $sHex;     //hex string without 0x
        $v = $vValue == 0 ? 27 : ($vValue == 1 ? 28 : $vValue); //27 or 28

        //with hex2bin it gives the same byte array as the javascript
        $rByteArray = unpack('C*', hex2bin($r));
        $sByteArray = unpack('C*', hex2bin($s));
        $rGmp = gmp_init("0x" . $r);
        $sGmp = gmp_init("0x" . $s);

        $recovery = $v - 27;
        if ($recovery !== 0 && $recovery !== 1) {
            throw new \Exception('Invalid signature v value');
        }

        $sig = new Signature();
        $publicKey = $sig->recoverPublicKey($rGmp, $sGmp, $messageGmp, $recovery);
        $publicKeyString = $publicKey["x"] . $publicKey["y"];

        return '0x' . substr($this->keccak256(hex2bin($publicKeyString)), -40);
    }

    /**
     * @method checks the address with help of a signed message
     * @param string $message - plaintext message that is signed
     * @param string $signature - signed message hex data
     * @param string $address - address to be verified
     * @return boolean true if signature address and provided address is same.
     */
    public function verifyAddress($message, $signature, $address)
    {
        $recoverAddress = Str::lower($this->recoverAddress($message, $signature));
        if (Str::lower($address) == $recoverAddress) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * @return hex of a string.
     */
    public function strToHex($string)
    {
        $hex = unpack('H*', $string);
        return '0x' . array_shift($hex);
    }

    /**
     * @return string Keccak256 hash of a given string
     */
    public function keccak256($str)
    {
        return '0x' . Keccak::hash($str, 256);
    }
}
