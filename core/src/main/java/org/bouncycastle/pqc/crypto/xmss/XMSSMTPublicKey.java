package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * XMSSMT Public Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSMTPublicKey implements XMSSStoreableObject {
	
	private int oid;
	
	private byte[] root;
	
	private byte[] publicSeed;
	
	private XMSSMT xmssMt;
	
	public XMSSMTPublicKey(XMSSMT xmssMt) {
		super();
		if (xmssMt == null) {
			throw new NullPointerException("xmss == null");
		}	
		this.xmssMt = xmssMt;
		publicSeed = xmssMt.getPublicSeed();
	}
	
	public byte[] toByteArray() {
		/* oid || root || seed */
		int n = xmssMt.getParams().getDigestSize();
//		int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		int totalSize = rootSize + publicSeedSize;//oidSize + 
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy oid */
//		XMSSUtil.intToBytesBigEndianOffset(out, oid, position);
//		position += oidSize;
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
		int n = xmssMt.getParams().getDigestSize();
//		int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		int totalSize = rootSize + publicSeedSize;//oidSize + 
		if (in.length != totalSize) {
			throw new ParseException("public key has wrong size", 0);
		}
		int position = 0;
//		oid = XMSSUtil.bytesToIntBigEndian(in, position);
//		if (oid != xmssMt.getParams().getOid().getOid()) {
//			throw new ParseException("public key not compatible with current instance parameters", 0);
//		}
//		position += oidSize;
		root = XMSSUtil.extractBytesAtOffset(in, position, rootSize);
		position += rootSize;
		publicSeed = XMSSUtil.extractBytesAtOffset(in, position, rootSize);
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
