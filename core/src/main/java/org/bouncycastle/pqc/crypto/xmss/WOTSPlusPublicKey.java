package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ public key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class WOTSPlusPublicKey {

	private byte[][] publicKey;
	
	public WOTSPlusPublicKey(byte[][] publicKey) {
		super();
		this.publicKey = publicKey;
	}
	
	public byte[][] toByteArray() {
		return XMSSUtil.byteArrayDeepCopy(publicKey);
	}
}
