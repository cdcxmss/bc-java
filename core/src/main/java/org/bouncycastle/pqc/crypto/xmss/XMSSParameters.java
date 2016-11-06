package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class XMSSParameters {
	
	private WinternitzOTSPlusParameters wotsPlusParams;
	
	/**
	 * the length in bytes of the message digest as well as of each node
	 */
	private int n;
	
	/**
	 * the height (number of levels - 1) of the tree
	 */
	private int h;
	
//	private SecureRandom prng;
//	
//	private Digest digest;
	
	/**
	 * Constructor
	 * @param n length in bytes of the message digest as well as of each node
	 * @param h the height (number of levels - 1) of the tree
	 * @param w the Winternitz parameter {4, 16}
	 */
	public XMSSParameters(int n, int h, int w, Digest digest, SecureRandom prng){
		this.n = n;
		this.h = h;
//		digest = new SHA256Digest();
//		prng = new SecureRandom();
		wotsPlusParams = new WinternitzOTSPlusParameters(digest, prng);
	}

	public WinternitzOTSPlusParameters getWotsPlusParams() {
		return wotsPlusParams;
	}

	public int getN() {
		return n;
	}

	public int getH() {
		return h;
	}
	
	

}
