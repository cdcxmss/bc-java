package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class XMSSParameters {
	
	/**
	 * WOTS+ scheme.
	 */
	private WinternitzOTSPlus wotsPlus;

	/**
	 * The height (number of levels - 1) of the tree.
	 */
	private int height;
	
	/**
	 * Keyed Hash Function.
	 */
	private KeyedHashFunction khf;
	
	/**
	 * XMSS Constructor...
	 * @param height Height of tree.
	 * @param digest Digest to use.
	 * @param prng PRNG.
	 */
	public XMSSParameters(int height, Digest digest, SecureRandom prng) {
		super();
		if (prng == null) {
			throw new NullPointerException("prng == null");
		}
		WinternitzOTSPlusParameters wotsPlusParams = new WinternitzOTSPlusParameters(digest, prng);
		wotsPlus = new WinternitzOTSPlus(wotsPlusParams);
		khf = new KeyedHashFunction(wotsPlus.getParams().getDigest());
	}
	
	public WinternitzOTSPlus getWotsPlus() {
		return wotsPlus;
	}
}
