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
	
	/**
	 * Constructor
	 * @param h the height (number of levels - 1) of the tree
	 */
	public XMSSParameters(int h, Digest digest, SecureRandom prng){
		this.n = digest.getDigestSize();
		this.h = h;
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
