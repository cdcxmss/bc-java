package org.bouncycastle.pqc.crypto.xmss;

/**
 * XMSS Public Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSPublicKey {

	private byte[] root;
	private byte[] publicSeed;
	
	public XMSSPublicKey(XMSS xmss, byte[] root, byte[] publicSeed) {
		super();
		if (xmss == null) {
			throw new NullPointerException("xmss == null");
		}
		int n = xmss.getParams().getDigestSize();
		if (root.length != n) {
			throw new IllegalArgumentException("length of root must be equal to length of digest");
		}
		if (publicSeed.length != n) {
			throw new IllegalArgumentException("length of publicSeed must be equal to length of digest");
		}
		this.root = root;
		this.publicSeed = publicSeed;
	}
	
	public byte[] getRoot() {
		return root;
	}
	
	public byte[] getPublicSeed() {
		return publicSeed;
	}
}
