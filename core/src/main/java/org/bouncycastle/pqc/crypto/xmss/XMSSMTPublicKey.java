package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * XMSSMT Public Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMTPublicKey implements XMSSStoreableObjectInterface {
	
	private int oid;
	private byte[] root;
	private byte[] publicSeed;
	private XMSSMTParameters params;
	
	public XMSSMTPublicKey(XMSSMTParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}	
		this.params = params;
	}
	
	public byte[] toByteArray() {
		/* oid || root || seed */
		int n = params.getDigestSize();
		//int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		int totalSize = rootSize + publicSeedSize;
		//int totalSize = oidSize + rootSize + publicSeedSize;
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
		int n = params.getDigestSize();
		//int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		int totalSize = rootSize + publicSeedSize;
		if (in.length != totalSize) {
			throw new ParseException("public key has wrong size", 0);
		}
		int position = 0;
		/*
		oid = XMSSUtil.bytesToIntBigEndian(in, position);
		if (oid != params.getOid().getOid()) {
			throw new ParseException("wrong oid", 0);
		}
		position += oidSize;
		*/
		root = XMSSUtil.extractBytesAtOffset(in, position, rootSize);
		position += rootSize;
		publicSeed = XMSSUtil.extractBytesAtOffset(in, position, publicSeedSize);
	}
	
	public byte[] getRoot() {
		return root;
	}
	
	public byte[] getPublicSeed() {
		return publicSeed;
	}
	
	public void setRoot(byte[] root){
		this.root = root;
	}

	public void setPublicSeed(byte[] seed) {
		publicSeed = seed;
	}
}
