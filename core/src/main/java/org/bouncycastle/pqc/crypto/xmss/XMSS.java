package org.bouncycastle.pqc.crypto.xmss;

/**
 * XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSS {

	private XMSSParameters params;
	private WinternitzOTSPlus wotsPlus;
	private byte[] publicSeed;
	private XMSSPrivateKey privateKey;
	private XMSSPublicKey publicKey;
	
	public XMSS(XMSSParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		publicSeed = new byte[params.getDigestSize()];
		params.getPRNG().nextBytes(publicSeed);
		WinternitzOTSPlusParameters wotsPlusParams = new WinternitzOTSPlusParameters(params.getDigest(), params.getPRNG());
		wotsPlus = new WinternitzOTSPlus(wotsPlusParams, publicSeed);
	}
	
	public void genKeyPair() {
		
	}
	
	private byte[] randomizeHash(byte[] left, byte[] right, XMSSAddress address) {
		int n = params.getDigestSize();
		if (left.length != n) {
			throw new IllegalArgumentException("size of left needs to be equal to size of digest");
		}
		if (right.length != n) {
			throw new IllegalArgumentException("size of right needs to be equal to size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		address.setKeyAndMask(0);
		byte[] key = params.getKHF().PRF(publicSeed, address.toByteArray());
		address.setKeyAndMask(1);
		byte[] bitmask0 = params.getKHF().PRF(publicSeed, address.toByteArray());
		address.setKeyAndMask(2);
		byte[] bitmask1 = params.getKHF().PRF(publicSeed, address.toByteArray());
		byte[] tmpMask = new byte[2 * n];
		for (int i = 0; i < n; i++) {
			tmpMask[i] = (byte)(left[i] ^ bitmask0[i]);
		}
		for (int i = 0; i < n; i++) {
			tmpMask[i+n] = (byte)(right[i] ^ bitmask1[i]);
		}
		return params.getKHF().H(key, tmpMask);
	}
	
	private byte[] lTree(LTreeAddress address) {
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		byte[][] publicKey = XMSSUtil.cloneArray(wotsPlus.getPublicKey());
		int len = wotsPlus.getParams().getLen();
		address.setTreeHeight(0);
		while (len > 1) {
			for (int i = 0; i < (int)Math.floor((double) len / 2); i++) {
				address.setTreeIndex(i);
				publicKey[i] = randomizeHash(publicKey[2 * i], publicKey[(2 * i) + 1], address);
			}
			if (len % 2 == 1) {
				publicKey[(int)Math.floor((double)len / 2)] = publicKey[len - 1];
			}
			len = (int)Math.ceil((double) len / 2);
			address.setTreeHeight(address.getTreeHeight() + 1);
		}
		return publicKey[0];
	}
	
	private XMSSNode treeHash() {
		return null;
	}
	
	public XMSSParameters getParams() {
		return params;
	}
	
	public byte[] getPublicSeed() {
		return publicSeed;
	}
}
