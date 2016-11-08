package org.bouncycastle.pqc.crypto.xmss;

/**
 * XMSS Private Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSPrivateKey {

	private XMSS xmss;
	private int index;
	private byte[] secretKeySeed;
	private byte[] secretKeyPRF;
	private byte[] publicSeed;
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
		return secretKeySeed;
	}

	public byte[] getSecretKeyPRF() {
		return secretKeyPRF;
	}

	public byte[] getPublicSeed() {
		return publicSeed;
	}

	public byte[] getRoot() {
		return root;
	}
	
	public void setRoot(byte[] root) {
		if (root.length != xmss.getParams().getDigestSize()) {
			throw new IllegalArgumentException("size of root needs to be equal size of digest");
		}
		this.root = root;
	}
}
