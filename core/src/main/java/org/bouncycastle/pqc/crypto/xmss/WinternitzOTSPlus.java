package org.bouncycastle.pqc.crypto.xmss;

/**
 * This class implements the WOTS+ one-time signature system
 * as described in draft-irtf-cfrg-xmss-hash-based-signatures-06.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class WinternitzOTSPlus {

	/**
	 * The WOTS+ parameters
	 */
	private WinternitzOTSPlusParameters params;
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
		int len = params.getLen();
		int n = params.getDigestSize();
		privateKey = new byte[len][n];
		int winternitzParameter = params.getWinternitzParameter();
		publicKey = new byte[len][winternitzParameter];
	}
	
	public void genKeyPair() {
		genPrivateKey();
		genPublicKey();
	}
	
	private void genPrivateKey() {
		for (int i = 0; i < params.getLen(); i++) {
			params.getPRNG().nextBytes(privateKey[i]);
		}
	}
	
	private void genPublicKey() {
		
	}
	
	public byte[][] getPrivateKey() {
		return privateKey;
	}
}
