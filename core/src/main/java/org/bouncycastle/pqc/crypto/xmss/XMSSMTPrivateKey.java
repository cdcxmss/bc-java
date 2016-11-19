package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

public class XMSSMTPrivateKey  implements XMSSStoreableObject {
	
	/**
	 * single (ceil(h / 8))-byte index
	 */
	private int index;
	
	/**
	 * 
	 */
	private byte[] secretKeySeed;
	
	/**
	 * single n-byte pseudorandom function key
	 */
	private byte[] secretKeyPRF;
	
	/**
	 * 
	 */
	private byte[] publicSeed;
	
	/**
	 * 
	 */
	private byte[] root;
	
	/**
	 * 
	 */
	private XMSSMTParameters params;
	
	/**
	 * 
	 * @param params
	 */
	public XMSSMTPrivateKey(XMSSMTParameters params) {
		super();
		this.params = params;
		index = 0;
		int n = params.getDigestSize();
		secretKeySeed = new byte[n];
		params.getPRNG().nextBytes(secretKeySeed);
		secretKeyPRF = new byte[n];
		params.getPRNG().nextBytes(secretKeyPRF);
		publicSeed = new byte[params.getDigestSize()];
		this.root = new byte[n];
	}
	
	@Override
	public byte[] toByteArray() {
		/* index || secretKeySeed || secretKeyPRF || publicSeed || root */
		int n = params.getDigestSize();
		int indexSize = (int) Math.ceil(params.getTotalHeight() / (double) 8);
		int secretKeySize = n;
		int secretKeyPRFSize = n;
		int publicSeedSize = n;
		int rootSize = n;
		int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy index */
		XMSSUtil.intToBytesBigEndianOffset(out, index, position);
		position += indexSize;
		/* copy secretKeySeed */
		XMSSUtil.copyBytesAtOffset(out, secretKeySeed, position);
		position += secretKeySize;
		/* copy secretKeyPRF */
		XMSSUtil.copyBytesAtOffset(out, secretKeyPRF, position);
		position += secretKeyPRFSize;
		/* copy publicSeed */
		XMSSUtil.copyBytesAtOffset(out, publicSeed, position);
		position += publicSeedSize;
		/* copy root */
		XMSSUtil.copyBytesAtOffset(out, root, position);
		return out;
	}
	
	@Override
	public void parseByteArray(byte[] in) throws ParseException {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		int n = params.getDigestSize();
		int height = params.getHeight(); // totalHeight, Layers ??
		int indexSize = (int) Math.ceil(params.getTotalHeight() / (double) 8);
		int secretKeySize = n;
		int secretKeyPRFSize = n;
		int publicSeedSize = n;
		int rootSize = n;
		int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
		if (in.length != totalSize) {
			throw new ParseException("private key has wrong size", 0);
		}
		int position = 0;
		index = XMSSUtil.bytesToIntBigEndian(in, position);
		if (!XMSSUtil.isIndexValid(height, index)) {
			throw new ParseException("index out of bounds", 0);
		}
		position += indexSize;
		secretKeySeed = XMSSUtil.extractBytesAtOffset(in, position, secretKeySize);
		position += secretKeySize;
		secretKeyPRF = XMSSUtil.extractBytesAtOffset(in, position, secretKeyPRFSize);
		position += secretKeyPRFSize;
		publicSeed = XMSSUtil.extractBytesAtOffset(in, position, publicSeedSize);
		position += publicSeedSize;
		root = XMSSUtil.extractBytesAtOffset(in, position, rootSize);
	}
	
	public int getIndex() {
		return index;
	}

	public void setIndex(int index) {
		this.index = index;
	}

	public byte[] getSecretKeySeed() {
		return secretKeySeed;
	}

	public void setSecretKeySeed(byte[] secretKeySeed) {
		this.secretKeySeed = secretKeySeed;
	}

	public byte[] getSecretKeyPRF() {
		return secretKeyPRF;
	}

	public void setSecretKeyPRF(byte[] secretKeyPRF) {
		this.secretKeyPRF = secretKeyPRF;
	}

	public byte[] getPublicSeed() {
		return publicSeed;
	}

	public void setPublicSeed(byte[] publicSeed) {
		this.publicSeed = publicSeed;
	}

	public byte[] getRoot() {
		return root;
	}

	public void setRoot(byte[] root) {
		this.root = root;
	}

	public XMSSMTParameters getParams() {
		return params;
	}

	public void setParams(XMSSMTParameters params) {
		this.params = params;
	}

}
