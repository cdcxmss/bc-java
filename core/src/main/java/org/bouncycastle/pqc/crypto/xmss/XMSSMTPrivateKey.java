package org.bouncycastle.pqc.crypto.xmss;


public class XMSSMTPrivateKey {
	
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
	
	private XMSSMTParameters params;
	
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
