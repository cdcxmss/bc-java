package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ public key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class WOTSPlusPublicKey {

	private byte[][] publicKey;
	
	protected WOTSPlusPublicKey(WOTSPlusParameters params, byte[][] publicKey) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		if (XMSSUtil.hasNullPointer(publicKey)) {
			throw new NullPointerException("publicKey byte array == null");
		}
		if (publicKey.length != params.getLen()) {
			throw new IllegalArgumentException("wrong publicKey size");
		}
		this.publicKey = publicKey;
	}
	
	protected byte[][] toByteArray() {
		return XMSSUtil.cloneArray(publicKey);
	}
}
