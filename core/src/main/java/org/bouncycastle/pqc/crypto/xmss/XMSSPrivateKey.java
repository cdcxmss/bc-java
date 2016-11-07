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

	private List<byte[]> wotsPlusPrivateKeys;
	private int index;
	byte[] secretKey;
	byte[] root;
	byte[] publicSeed;
	
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
