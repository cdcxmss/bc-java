package org.bouncycastle.pqc.crypto.xmss;

import org.ietf.jgss.Oid;

public class XMSSMTPublicKey {
	
	private Oid oid;
	
	private byte[] root;
	
	private byte[] publicSeed;
	
	public XMSSMTPublicKey(XMSS xmss, byte[] root) {
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
