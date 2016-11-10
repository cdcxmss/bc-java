package org.bouncycastle.pqc.crypto.xmss;

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
		int n = xmss.getParams().getDigestSize();
		/* generate keys */
		secretKeySeed = new byte[n];
		xmss.getParams().getPRNG().nextBytes(secretKeySeed);
		secretKeyPRF = new byte[n];
		xmss.getParams().getPRNG().nextBytes(secretKeyPRF);
		publicSeed = xmss.getPublicSeed();
		root = new byte[n];
	}
	
	protected byte[] getWOTSPlusSecretKey(int index) {
		return xmss.getParams().getKHF().PRF(secretKeySeed, XMSSUtil.toBytesBigEndian(index, 32));
	}
	
	public int getIndex() {
		return index;
	}
	
	public void setIndex(int index) {
		if (index > (1 << xmss.getParams().getHeight()) - 1) {
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

	public byte[] getRoot() {
		return XMSSUtil.byteArrayDeepCopy(root);
	}
	
	public void setRoot(byte[] root) {
		if (root.length != xmss.getParams().getDigestSize()) {
			throw new IllegalArgumentException("size of root needs to be equal size of digest");
		}
		this.root = root;
	}
}
