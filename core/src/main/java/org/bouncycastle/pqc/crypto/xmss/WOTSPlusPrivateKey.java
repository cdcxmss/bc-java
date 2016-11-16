package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ private key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class WOTSPlusPrivateKey {

	private byte[][] privateKey;
	
	protected WOTSPlusPrivateKey(WOTSPlusParameters params, byte[][] privateKey) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		if (privateKey == null) {
			throw new NullPointerException("privateKey == null");
		}
		if (XMSSUtil.hasNullPointer(privateKey)) {
			throw new NullPointerException("privateKey byte array == null");
		}
		if (privateKey.length != params.getLen()) {
			throw new IllegalArgumentException("wrong privateKey size");
		}
		this.privateKey = privateKey;
	}
	
	protected byte[][] toByteArray() {
		return XMSSUtil.cloneArray(privateKey);
	}
}
