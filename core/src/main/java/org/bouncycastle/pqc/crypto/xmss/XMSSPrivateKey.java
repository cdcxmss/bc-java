package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * XMSS Private Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSPrivateKey {

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
	
	public byte[][] toByteArray() {
		int n = xmss.getParams().getDigestSize();
		byte[][] privateKey = new byte[5][];
		/* copy index */
		privateKey[0] = XMSSUtil.toBytesBigEndian(index, 32);
		/* copy secret key seed */
		privateKey[1] = XMSSUtil.cloneArray(secretKeySeed);
		/* copy secret key prf */
		privateKey[2] = XMSSUtil.cloneArray(secretKeyPRF);
		/* copy public seed */
		privateKey[3] = XMSSUtil.cloneArray(publicSeed);
		/* copy root */
		privateKey[4] = XMSSUtil.cloneArray(root);
		return privateKey;
	}
	
	public void parseByteArray(byte[][] privateKey) throws ParseException {
		if (XMSSUtil.hasNullPointer(privateKey)) {
			throw new NullPointerException("privateKey has null pointers");
		}
		if (privateKey.length != 5) {
			throw new ParseException("wrong size", 0);
		}
		int n = xmss.getParams().getDigestSize();

		/* parse index */
		byte[] index = privateKey[0];
		if (index.length != 32) {
			throw new ParseException("index must be 32 bytes", 0);
		}
		int tmpIndex = XMSSUtil.bytesToIntBigEndian(index, 28);
		if (!isIndexValid(tmpIndex)) {
			throw new IllegalArgumentException("index out of bounds");
		}
		this.index = tmpIndex;

		/* parse secret key seed */
		byte[] secretKeySeed = XMSSUtil.cloneArray(privateKey[1]);
		if (secretKeySeed.length != n) {
			throw new ParseException("secret key seed needs to be equal to size of digest", 0);
		}
		this.secretKeySeed = secretKeySeed;

		/* parse secret key PRF */
		byte[] secretKeyPRF = XMSSUtil.cloneArray(privateKey[2]);
		if (secretKeyPRF.length != n) {
			throw new ParseException("secret key PRF needs to be equal to size of digest", 0);
		}
		this.secretKeyPRF = secretKeyPRF;

		/* parse public seed */
		byte[] publicSeed = XMSSUtil.cloneArray(privateKey[3]);
		if (publicSeed.length != n) {
			throw new ParseException("publicSeed needs to be equal to size of digest", 0);
		}
		this.publicSeed = publicSeed;

		/* parse root */
		byte[] root = XMSSUtil.cloneArray(privateKey[4]);
		if (root.length != n) {
			throw new ParseException("root needs to be equal to size of digest", 0);
		}
		this.root = root;
	}
	
	private boolean isIndexValid(int index) {
		if (index > (1 << xmss.getParams().getHeight()) - 1) {
			return false;
		}
		return true;
	}
	
	public int getIndex() {
		return index;
	}
	
	public void setIndex(int index) {
		if (!isIndexValid(index)) {
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
