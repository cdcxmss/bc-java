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
	
	public void generateKeys() {
		int n = xmss.getParams().getDigestSize();
		secretKeySeed = new byte[n];
		xmss.getParams().getPRNG().nextBytes(secretKeySeed);
		secretKeyPRF = new byte[n];
		xmss.getParams().getPRNG().nextBytes(secretKeyPRF);
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
		byte[] secretKeySeed = XMSSUtil.byteArrayDeepCopy(privateKey[1]);
		if (secretKeySeed.length != n) {
			throw new ParseException("secret key seed needs to be equal to size of digest", 0);
		}
		this.secretKeySeed = secretKeySeed;

		/* parse secret key PRF */
		byte[] secretKeyPRF = XMSSUtil.byteArrayDeepCopy(privateKey[2]);
		if (secretKeyPRF.length != n) {
			throw new ParseException("secret key PRF needs to be equal to size of digest", 0);
		}
		this.secretKeyPRF = secretKeyPRF;

		/* parse public seed */
		byte[] publicSeed = XMSSUtil.byteArrayDeepCopy(privateKey[3]);
		if (publicSeed.length != n) {
			throw new ParseException("publicSeed needs to be equal to size of digest", 0);
		}
		this.publicSeed = publicSeed;

		/* parse root */
		byte[] root = XMSSUtil.byteArrayDeepCopy(privateKey[4]);
		if (root.length != n) {
			throw new ParseException("root needs to be equal to size of digest", 0);
		}
		this.root = root;
	}
	
	public byte[][] toByteArray() {
		int n = xmss.getParams().getDigestSize();
		byte[][] privateKey = new byte[5][];
		/* copy index */
		privateKey[0] = XMSSUtil.toBytesBigEndian(index, 32);
		/* copy secret key seed */
		privateKey[1] = XMSSUtil.byteArrayDeepCopy(secretKeySeed);
		/* copy secret key prf */
		privateKey[2] = XMSSUtil.byteArrayDeepCopy(secretKeyPRF);
		/* copy public seed */
		privateKey[3] = XMSSUtil.byteArrayDeepCopy(publicSeed);
		/* copy root */
		privateKey[4] = XMSSUtil.byteArrayDeepCopy(root);
		return privateKey;
	}
	
	protected byte[] getWOTSPlusSecretKey(int index) {
		return xmss.getParams().getKHF().PRF(secretKeySeed, XMSSUtil.toBytesBigEndian(index, 32));
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
		return XMSSUtil.byteArrayDeepCopy(secretKeySeed);
	}

	public byte[] getSecretKeyPRF() {
		return XMSSUtil.byteArrayDeepCopy(secretKeyPRF);
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

	public byte[] getRoot() {
		return XMSSUtil.byteArrayDeepCopy(root);
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
