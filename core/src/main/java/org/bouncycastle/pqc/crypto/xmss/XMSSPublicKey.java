package org.bouncycastle.pqc.crypto.xmss;

import org.ietf.jgss.Oid;

/**
 * XMSS Public Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSPublicKey {

	private Oid oid;
	private byte[] root;
	private byte[] publicSeed;
	
	public XMSSPublicKey(XMSS xmss, byte[] root) {
		super();
		if (xmss == null) {
			throw new NullPointerException("xmss == null");
		}
		int n = xmss.getParams().getDigestSize();
		if (root.length != n) {
			throw new IllegalArgumentException("length of root must be equal to length of digest");
		}
		this.root = root;
		publicSeed = xmss.getPublicSeed();
	}
	
	public byte[] toByteArray() {
		/* TODO */
		return null;
	}
	
	public byte[] getRoot() {
		return root;
	}
	
	public byte[] getPublicSeed() {
		return publicSeed;
	}
}
