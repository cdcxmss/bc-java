package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ signature.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class WOTSPlusSignature {

	private byte[][] signature;
	
	public WOTSPlusSignature(byte[][] signature) {
		super();
		this.signature = signature;
	}
	
	public byte[][] toByteArray() {
		return XMSSUtil.byteArrayDeepCopy(signature);
	}
}
