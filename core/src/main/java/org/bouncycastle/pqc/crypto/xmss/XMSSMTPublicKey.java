package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

import org.ietf.jgss.Oid;

public class XMSSMTPublicKey implements XMSSStoreableObject {
	
	private Oid oid;
	
	private byte[] root;
	
	private byte[] publicSeed;
	
	private XMSSMT xmssMt;
	
	public XMSSMTPublicKey(XMSSMT xmssMt, byte[] root) {
		super();
		if (xmssMt == null) {
			throw new NullPointerException("xmss == null");
		}
		int n = xmssMt.getParams().getDigestSize();
		if (root.length != n) {
			throw new IllegalArgumentException("length of root must be equal to length of digest");
		}
		this.root = root;
		publicSeed = xmssMt.getPublicSeed();
	}
	
	public byte[] toByteArray() {
		/* oid || root || seed */
		int n = xmssMt.getParams().getDigestSize();
		int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		int totalSize = oidSize + rootSize + publicSeedSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy oid */
		XMSSUtil.intToBytesBigEndianOffset(out, oid, position);
		position += oidSize;
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
		int oidSize = 4;
		int rootSize = n;
		int publicSeedSize = n;
		int totalSize = oidSize + rootSize + publicSeedSize;
		if (in.length != totalSize) {
			throw new ParseException("public key has wrong size", 0);
		}
		int position = 0;
		oid = XMSSUtil.bytesToIntBigEndian(in, position);
		if (oid != xmssMt.getParams().getOid().getOid()) {
			throw new ParseException("public key not compatible with current instance parameters", 0);
		}
		position += oidSize;
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

}
