package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;

/**
 * 
 * XMSS Parameters.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSParameters {

	private int height;
	private Digest digest;
	private int digestSize;
	private SecureRandom prng;
	private KeyedHashFunctions khf;
	private int winternitzParameter;
	
	/**
	 * XMSS Constructor...
	 * @param height Height of tree.
	 * @param digest Digest to use.
	 * @param prng PRNG.
	 */
	public XMSSParameters(int height, Digest digest, SecureRandom prng) {
		super();
		/*
		 * if height is greater than 30 integers overflow e.g. in loops...
		 * the current maximum supported is 2^30 signatures accordingly.
		 */
		if (height > 30) {
			throw new IllegalArgumentException("maximum height is 30");
		}
		if (digest == null) {
			throw new NullPointerException("digest == null");
		}
		if (prng == null) {
			throw new NullPointerException("prng == null");
		}
		if (!XMSSUtil.isValidDigest(digest)) {
			throw new IllegalArgumentException(digest.getAlgorithmName() + "(" + digest.getDigestSize() + ")" + "is not allowed");
		};
		this.height = height;
		this.digest = digest;
		this.digestSize = digest.getDigestSize();
		this.prng = prng;
		khf = new KeyedHashFunctions(digest);
		winternitzParameter = 16;
	}

	public int getHeight() {
		return height;
	}

	public Digest getDigest() {
		return digest;
	}

	public int getDigestSize() {
		return digestSize;
	}

	public SecureRandom getPRNG() {
		return prng;
	}

	public KeyedHashFunctions getKHF() {
		return khf;
	}
	
	public int getWinternitzParameter() {
		return winternitzParameter;
	}
}
