<?php

namespace Desnake\Web3signature;

class Signature
{
    public $a;
    public $b;
    public $p;
    public $n;
    public $G;

    public function __construct()
    {
        $this->a = gmp_init('0', 10);
        $this->b = gmp_init('7', 10);
        $this->p = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
        $this->n = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);

        $this->G = array(
            'x' => gmp_init('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
            'y' => gmp_init('32670510020758816978083085130507043184471273380659243275938904335757337482424')
        );
    }

    public function recoverpublicKey($R, $S, $hash, $recoveryFlags){
		$a = $this->a;
		$b = $this->b;
		$G = $this->G;
		$n = $this->n;
		$p = $this->p;

		$isYEven = ($recoveryFlags & 1) != 0;
		$isSecondKey = ($recoveryFlags & 2) != 0;

		// PointMathGMP::mulPoint wants HEX String
		$e = gmp_strval($hash, 16);
		$s = gmp_strval($S, 16);

		// Precalculate (p + 1) / 4 where p is the field order
		// $p_over_four is GMP
		static $p_over_four; // XXX just assuming only one curve/prime will be used
		if (!$p_over_four) {
			$p_over_four = gmp_div(gmp_add($p, 1), 4);
		}

		// 1.1 Compute x
		// $x is GMP
		if (!$isSecondKey) {
			$x = $R;
		} else {
			$x = gmp_add($R, $n);
		}

		// 1.3 Convert x to point
		// $alpha is GMP
		$alpha = gmp_mod(gmp_add(gmp_add(gmp_pow($x, 3), gmp_mul($a, $x)), $b), $p);
		// $beta is DEC String (INT)
		$beta = gmp_strval(gmp_powm($alpha, $p_over_four, $p));

		// If beta is even, but y isn't or vice versa, then convert it,
		// otherwise we're done and y == beta.
		if (PointMathGMP::isEvenNumber($beta) == $isYEven) {
			// gmp_sub function will convert the DEC String "$beta" into a GMP
			// $y is a GMP 
			$y = gmp_sub($p, $beta);
		} else {
			// $y is a GMP
			$y = gmp_init($beta);
		}

		// 1.4 Check that nR is at infinity (implicitly done in construtor) -- Not reallly
		// $Rpt is Array(GMP, GMP)
		$Rpt = array('x' => $x, 'y' => $y);

		// 1.6.1 Compute a candidate public static key Q = r^-1 (sR - eG)
		// $rInv is a HEX String
		$rInv = gmp_strval(gmp_invert($R, $n), 16);

		// $eGNeg is Array (GMP, GMP)
		$eGNeg = PointMathGMP::negatePoint(PointMathGMP::mulPoint($e, $G, $a, $b, $p));

		$sR = PointMathGMP::mulPoint($s, $Rpt, $a, $b, $p);

		$sR_plus_eGNeg = PointMathGMP::addPoints($sR, $eGNeg, $a, $p);

		// $Q is Array (GMP, GMP)
		$Q = PointMathGMP::mulPoint($rInv, $sR_plus_eGNeg, $a, $b, $p);

		// Q is the derrived public static key
		// $pubkey is Array (HEX String, HEX String)
		// Ensure it's always 64 HEX Charaters
        $pubKey['x'] = str_pad(gmp_strval($Q['x'], 16), 64, 0, STR_PAD_LEFT);
        $pubKey['y'] = str_pad(gmp_strval($Q['y'], 16), 64, 0, STR_PAD_LEFT);

		return $pubKey;
	}
}
