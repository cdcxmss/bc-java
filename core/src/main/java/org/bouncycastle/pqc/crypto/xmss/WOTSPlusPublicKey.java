package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ public key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class WOTSPlusPublicKey {

	private byte[][] publicKey;
	
	public WOTSPlusPublicKey(WOTSPlusParameters params, byte[][] publicKey) {
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
	
	public byte[][] toByteArray() {
		return XMSSUtil.byteArrayDeepCopy(publicKey);
	}
}
