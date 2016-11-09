package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ private key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class WOTSPlusPrivateKey {

	private byte[][] privateKey;
	
	public WOTSPlusPrivateKey(byte[][] privateKey) {
		super();
		this.privateKey = privateKey;
	}
	
	public byte[][] toByteArray() {
		return privateKey;
	}
}
