package org.bouncycastle.pqc.crypto.xmss;

import java.util.ArrayList;
import java.util.List;

/**
 * 
 * XMSS Private Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSPrivateKey {

	/**
	 * WOTS+ private keys
	 */
	private List<byte[]> wotsPlusPrivateKeys;
	
	/**
	 * The leaf index idx of the next WOTS+ private key that has not yet been used
	 */
	private int index;
	byte[] secretKey;
	
	/**
	 * the root node of the tree
	 */
	byte[] root;
	
	/**
	 * n-byte public seed used to pseudorandomly generate bitmasks and hash function keys
	 */
	byte[] publicSeed;
	
	/**
	 * Constructor
	 * @param xmssParams The parameters used for XMSS
	 */
	public XMSSPrivateKey(XMSSParameters xmssParams) {
		super();
		if (xmssParams == null) {
			throw new NullPointerException("xmssParams == null");
		}
		wotsPlusPrivateKeys = new ArrayList<byte[]>();
		secretKey = new byte[xmssParams.getWotsPlus().getParams().getDigestSize()];
		xmssParams.getWotsPlus().getParams().getPRNG().nextBytes(secretKey);
		root = new byte[xmssParams.getWotsPlus().getParams().getDigestSize()];
		publicSeed = xmssParams.getWotsPlus().getPublicSeed();
		generateWotsPlusPrivateKeys();
	}
	
	private void generateWotsPlusPrivateKeys() {
		
	}
}
