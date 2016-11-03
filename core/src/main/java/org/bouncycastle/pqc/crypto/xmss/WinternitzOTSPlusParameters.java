package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

/**
 * Parameters for the WOTS+ one-time signature system as described in draft-irtf-cfrg-xmss-hash-based-signatures-06.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class WinternitzOTSPlusParameters {

	/**
	 * Digest used in WOTS+.
	 */
	private Digest digest;
	
	/**
	 * The message digest size.
	 */
	private int digestSize;
	
	/**
	 * The Winternitz parameter (currently fixed to 16).
	 */
	private int winternitzParameter;
	
	/**
	 * len1.
	 */
	private int len1;
	
	/**
	 * len2.
	 */
	private int len2;
	
	/**
	 * The number of n-byte string elements in a WOTS+ secret key, public key, and signature.
	 */
	private int len;
	
	/**
	 * Constructor...
	 * @param digest The digest used for WOTS+.
	 */
	public WinternitzOTSPlusParameters(Digest digest) {
		super();
		if (digest == null) {
			throw new NullPointerException("digest == null");
		}
		if (!isValidDigest(digest)) {
			throw new IllegalArgumentException(digest.getAlgorithmName() + "(" + digest.getDigestSize() + ")" + "is not allowed");
		};
		this.digest = digest;
		digestSize = digest.getDigestSize();
		winternitzParameter = 16;
		setLen();
	}
	
	/**
	 * Checks whether the digest is allowed according to draft-irtf-cfrg-xmss-hash-based-signatures-06.
	 * @param digest The digest to be validated.
	 * @return true if digest is valid false else.
	 */
	private boolean isValidDigest(Digest digest) {
		if (digest instanceof SHA256Digest || digest instanceof SHA512Digest) {
			return true;
		}
		return false;
	}
	
	/**
	 * Sets the len values from the message digest size and Winternitz parameter.
	 */
	private void setLen() {
		len1 = (int) Math.ceil((8 * digestSize) / XMSSUtil.log2(winternitzParameter));
		len2 = (int) Math.floor(XMSSUtil.log2(len1 * (winternitzParameter - 1)) / XMSSUtil.log2(winternitzParameter)) + 1;
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
	 * Getter WinternitzParameter.
	 * @return winternitzParameter.
	 */
	public int getWinternitzParameter() {
		return winternitzParameter;
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
	
	/**
	 * Getter len.
	 * @return len.
	 */
	public int getLen() {
		return len;
	}
}
