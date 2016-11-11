package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

import org.ietf.jgss.Oid;

/**
 * XMSS Public Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSPublicKey {

	/**
	 * XMSS object.
	 */
	private XMSS xmss;
	private Oid oid;
	private byte[] root;
	private byte[] publicSeed;
	
	public XMSSPublicKey(XMSS xmss) {
		super();
		if (xmss == null) {
			throw new NullPointerException("xmss == null");
		}
		this.xmss = xmss;
	}
	
	public void parseByteArray(byte[][] publicKey) throws ParseException {
		if (XMSSUtil.hasNullPointer(publicKey)) {
			throw new NullPointerException("publicKey has null pointers");
		}
		if (publicKey.length != 2) {
			throw new ParseException("wrong size", 0);
		}
		int n = xmss.getParams().getDigestSize();
		
		/* parse root */
		byte[] root = XMSSUtil.byteArrayDeepCopy(publicKey[0]);
		if (root.length != n) {
			throw new ParseException("root needs to be equal to size of digest", 0);
		}
		this.root = root;
		/* parse public seed */
		byte[] publicSeed = XMSSUtil.byteArrayDeepCopy(publicKey[1]);
		if (publicSeed.length != n) {
			throw new ParseException("publicSeed needs to be equal to size of digest", 0);
		}
		this.publicSeed = publicSeed;
	}
	
	public byte[][] toByteArray() {
		byte[][] publicKey = new byte[2][];
		/* copy root */
		publicKey[0] = XMSSUtil.byteArrayDeepCopy(root);
		/* copy publicSeed */
		publicKey[1] = XMSSUtil.byteArrayDeepCopy(publicSeed);
		return publicKey;
	}
	
	public byte[] getRoot() {
		return XMSSUtil.byteArrayDeepCopy(root);
	}
	
	public void setRoot(byte[] root) {
		if (root == null) {
			throw new NullPointerException("root == null");
		}
		if (root.length != xmss.getParams().getDigestSize()) {
			throw new IllegalArgumentException("length of root must be equal to length of digest");
		}
		this.root = root;
	}
	
	public byte[] getPublicSeed() {
		return XMSSUtil.byteArrayDeepCopy(publicSeed);
	}
	
	public void setPublicSeed(byte[] publicSeed) {
		if (publicSeed == null) {
			throw new NullPointerException("publicSeed == null");
		}
		if (publicSeed.length != xmss.getParams().getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal size of digest");
		}
		this.publicSeed = publicSeed;
	}
}
