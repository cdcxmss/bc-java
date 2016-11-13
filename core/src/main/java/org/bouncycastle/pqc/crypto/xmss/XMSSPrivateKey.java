package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * XMSS Private Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSPrivateKey implements XMSSStoreableObject {

	/**
	 * XMSS object.
	 */
	private XMSS xmss;
	/**
	 * Index for WOTS+ keys (randomization factor).
	 */
	private int index;
	/**
	 * Secret for the derivation of WOTS+ secret keys.
	 */
	private byte[] secretKeySeed;
	/**
	 * Secret for the randomization of message digests during signature creation.
	 */
	private byte[] secretKeyPRF;
	/**
	 * Public seed for the randomization of hashes.
	 */
	private byte[] publicSeed;
	/**
	 * Public root of binary tree.
	 */
	private byte[] root;
	
	public XMSSPrivateKey(XMSS xmss) {
		super();
		if (xmss == null) {
			throw new NullPointerException("xmss == null");
		}
		this.xmss = xmss;
		index = 0;
	}
	
	@Override
	public byte[] toByteArray() {
		/* index || secretKeySeed || secretKeyPRF || publicSeed || root */
		int n = xmss.getParams().getDigestSize();
		int indexSize = 4;
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
		int n = xmss.getParams().getDigestSize();
		int height = xmss.getParams().getHeight();
		int indexSize = 4;
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
		if (!XMSSUtil.isIndexValid(xmss.getParams().getHeight(), index)) {
			throw new IllegalArgumentException("index out of bounds");
		}
		this.index = index;
	}
	
	public byte[] getSecretKeySeed() {
		return XMSSUtil.cloneArray(secretKeySeed);
	}
	
	public void setSecretKeySeed(byte[] secretKeySeed) {
		if (secretKeySeed == null) {
			throw new NullPointerException("secretKeySeed == null");
		}
		if (secretKeySeed.length != xmss.getParams().getDigestSize()) {
			throw new IllegalArgumentException("size of secretKeySeed needs to be equal size of digest");
		}
		this.secretKeySeed = secretKeySeed;
	}

	public byte[] getSecretKeyPRF() {
		return XMSSUtil.cloneArray(secretKeyPRF);
	}
	
	public void setSecretKeyPRF(byte[] secretKeyPRF) {
		if (secretKeyPRF == null) {
			throw new NullPointerException("secretKeyPRF == null");
		}
		if (secretKeyPRF.length != xmss.getParams().getDigestSize()) {
			throw new IllegalArgumentException("size of secretKeyPRF needs to be equal size of digest");
		}
		this.secretKeyPRF = secretKeyPRF;
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

	public byte[] getRoot() {
		return XMSSUtil.cloneArray(root);
	}
	
	public void setRoot(byte[] root) {
		if (root == null) {
			throw new NullPointerException("root == null");
		}
		if (root.length != xmss.getParams().getDigestSize()) {
			throw new IllegalArgumentException("size of root needs to be equal size of digest");
		}
		this.root = root;
	}
}
