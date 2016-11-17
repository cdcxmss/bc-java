package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * XMSS Public Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSPublicKey implements XMSSStoreableObject {

	/**
	 * XMSS object.
	 */
	private XMSS xmss;
	private int oid;
	private byte[] root;
	private byte[] publicSeed;
	
	public XMSSPublicKey(XMSS xmss) {
		super();
		if (xmss == null) {
			throw new NullPointerException("xmss == null");
		}
		this.xmss = xmss;
		oid = xmss.getParams().getOid().getOid();
	}
	
	@Override
	public byte[] toByteArray() {
		/* oid || root || seed */
		int n = xmss.getParams().getDigestSize();
		//int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		//int totalSize = oidSize + rootSize + publicSeedSize;
		int totalSize = rootSize + publicSeedSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy oid */
		/*
		XMSSUtil.intToBytesBigEndianOffset(out, oid, position);
		position += oidSize;
		*/
		/* copy root */
		XMSSUtil.copyBytesAtOffset(out, root, position);
		position += rootSize;
		/* copy public seed */
		XMSSUtil.copyBytesAtOffset(out, publicSeed, position);
		return out;
	}

	@Override
	public void parseByteArray(byte[] in) throws ParseException {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		int n = xmss.getParams().getDigestSize();
		//int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		//int totalSize = oidSize + rootSize + publicSeedSize;
		int totalSize = rootSize + publicSeedSize;
		if (in.length != totalSize) {
			throw new ParseException("public key has wrong size", 0);
		}
		int position = 0;
		/*
		oid = XMSSUtil.bytesToIntBigEndian(in, position);
		if (oid != xmss.getParams().getOid().getOid()) {
			throw new ParseException("public key not compatible with current instance parameters", 0);
		}
		position += oidSize;
		*/
		root = XMSSUtil.extractBytesAtOffset(in, position, rootSize);
		position += rootSize;
		publicSeed = XMSSUtil.extractBytesAtOffset(in, position, rootSize);
	}
	
	public int getOid() {
		return oid;
	}
	
	public void setOid(int oid) {
		this.oid = oid;
	}
	
	public byte[] getRoot() {
		return XMSSUtil.cloneArray(root);
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
		return XMSSUtil.cloneArray(publicSeed);
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
