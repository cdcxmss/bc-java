package org.bouncycastle.pqc.crypto.xmss;

/**
 * This class implements the WOTS+ one-time signature system
 * as described in draft-irtf-cfrg-xmss-hash-based-signatures-06.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class WinternitzOTSPlus {

	/**
	 * WOTS+ parameters.
	 */
	private WinternitzOTSPlusParameters params;
	
	/**
	 * Keyed Hash Function
	 */
	private KeyedHashFunction khf;
	
	/**
	 * WOTS+ private key.
	 */
	private byte[][] privateKey;
	/**
	 * WOTS+ public key.
	 */
	private byte[][] publicKey;
	
	/**
	 * Constructs a new WOTS+ one-time signature system based
	 * on the given WOTS+ parameters.
	 */
	public WinternitzOTSPlus(WinternitzOTSPlusParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		khf = new KeyedHashFunction(params.getDigest());
		int len = params.getLen();
		int n = params.getDigestSize();
		privateKey = new byte[len][n];
		publicKey = new byte[len][];
	}
	
	public void genKeyPair() {
		genPrivateKey();
		byte[] publicSeed = new byte[params.getDigestSize()];
		params.getPRNG().nextBytes(publicSeed);
		genPublicKey(publicSeed, new OTSHashAddress());
	}
	
	private void genPrivateKey() {
		for (int i = 0; i < params.getLen(); i++) {
			params.getPRNG().nextBytes(privateKey[i]);
		}
	}
	
	private void genPublicKey(byte[] publicSeed, OTSHashAddress address) {
		int n = params.getDigestSize();
		if (publicSeed.length != n) {
			throw new IllegalArgumentException("publicSeed needs to be " + n + "bytes");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		
		for (int i = 0; i < params.getLen(); i++) {
			address.setChainAddress(i);
			publicKey[i] = chain(privateKey[i], 0, params.getWinternitzParameter() - 1, publicSeed, address);
		}
	}
	
	private byte[] chain(byte[] X, int startIndex, int steps, byte[] seed, OTSHashAddress address) {
		int n = params.getDigestSize();
		if (X.length != n) {
			throw new IllegalArgumentException("X needs to be " + n + "bytes");
		}
		if (seed.length != n) {
			throw new IllegalArgumentException("seed needs to be " + n + "bytes");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}	
		if ((startIndex + steps) > params.getWinternitzParameter() - 1) {
			throw new IllegalArgumentException("max chain length must not be greater than w");
		}
		
		if (steps == 0) {
			return X;
		}
		
		byte[] tmp = chain(X, startIndex, steps - 1, seed, address);
		address.setHashAddress(startIndex + steps - 1);
		address.setKeyAndMask(0);
		byte[] key = khf.PRF(seed, address);
		address.setKeyAndMask(1);
		byte[] bitmask = khf.PRF(seed, address);
		byte[] tmpMasked = new byte[n];
		for (int i = 0; i < n; i++) {
			tmpMasked[i] = (byte)(tmp[i] ^ bitmask[i]);
		}
		tmp = khf.F(key, tmpMasked);
		return tmp;
	}
	
	public byte[][] getPublicKey() {
		return publicKey;
	}
}
