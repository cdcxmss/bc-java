package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.ietf.jgss.Oid;

/**
 * Parameters for the WOTS+ one-time signature system as described in draft-irtf-cfrg-xmss-hash-based-signatures-06.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class WOTSPlusParameters {

	/**
	 * Digest used in WOTS+.
	 */
	private Digest digest;
	
	/**
	 * The message digest size.
	 */
	private int digestSize;
	
	/**
	 * PRNG.
	 */
	private SecureRandom prng;
	
	/**
	 * The Winternitz parameter (currently fixed to 16).
	 */
	private int winternitzParameter;
	
	/**
	 * The number of n-byte string elements in a WOTS+ secret key, public key, and signature.
	 */
	private int len;

	/**
	 * len1.
	 */
	private int len1;
	
	/**
	 * len2.
	 */
	private int len2;
	
	/**
	 * oid.
	 */
	private Oid oid;
	
	/**
	 * Constructor...
	 * @param digest The digest used for WOTS+.
	 */
	public WOTSPlusParameters(Digest digest, SecureRandom prng) {
		super();
		if (digest == null) {
			throw new NullPointerException("digest == null");
		}
		if (prng == null) {
			throw new NullPointerException("prng == null");
		}
		if (!XMSSUtil.isValidDigest(digest)) {
			throw new IllegalArgumentException(digest.getAlgorithmName() + "(" + digest.getDigestSize() + ")" + "is not allowed");
		};
		this.digest = digest;
		digestSize = digest.getDigestSize();
		this.prng = prng;
		winternitzParameter = 16;
		setLen();
		// TODO getOidFromParams();
	}
	
	/**
	 * Sets the len values from the message digest size and Winternitz parameter.
	 */
	private void setLen() {
		len1 = (int)Math.ceil((double)(8 * digestSize) / XMSSUtil.log2(winternitzParameter));
		len2 = (int)Math.floor(XMSSUtil.log2(len1 * (winternitzParameter - 1)) / XMSSUtil.log2(winternitzParameter)) + 1;
		len = len1 + len2;
	}

	/**
	 * Getter digest.
	 * @return digest.
	 */
	public Digest getDigest() {
		return digest;
	}
	
	/**
	 * Getter digestSize.
	 * @return digestSize.
	 */
	public int getDigestSize() {
		return digestSize;
	}
	
	/**
	 * Getter PRNG.
	 * @return PRNG.
	 */
	public SecureRandom getPRNG() {
		return prng;
	}

	/**
	 * Getter WinternitzParameter.
	 * @return winternitzParameter.
	 */
	public int getWinternitzParameter() {
		return winternitzParameter;
	}
	
	/**
	 * Getter len.
	 * @return len.
	 */
	public int getLen() {
		return len;
	}
	
	/**
	 * Getter len1.
	 * @return len1.
	 */
	public int getLen1() {
		return len1;
	}
	
	/**
	 * Getter len2.
	 * @return len2.
	 */
	public int getLen2() {
		return len2;
	}
}
