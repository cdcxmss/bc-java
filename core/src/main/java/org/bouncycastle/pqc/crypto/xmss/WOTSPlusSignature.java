package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ signature.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class WOTSPlusSignature {

	private byte[][] signature;
	
	public WOTSPlusSignature(WOTSPlusParameters params, byte[][] signature) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (XMSSUtil.hasNullPointer(signature)) {
			throw new NullPointerException("signature byte array == null");
		}
		if (signature.length != params.getLen()) {
			throw new IllegalArgumentException("wrong signature size");
		}
		this.signature = signature;
	}
	
	public byte[][] toByteArray() {
		return XMSSUtil.byteArrayDeepCopy(signature);
	}
}
