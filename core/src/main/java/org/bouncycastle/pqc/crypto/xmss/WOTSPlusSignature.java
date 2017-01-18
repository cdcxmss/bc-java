package org.bouncycastle.pqc.crypto.xmss;

/**
 * WOTS+ signature.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class WOTSPlusSignature {

	private byte[][] signature;
	
	protected WOTSPlusSignature(WOTSPlusParameters params, byte[][] signature) {
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
		for (int i = 0; i < signature.length; i++) {
			if (signature[i].length != params.getDigestSize()) {
				throw new IllegalArgumentException("wrong privateKey format");
			}
		}
		this.signature = signature;
	}
	
	public byte[][] toByteArray() {
		return XMSSUtil.cloneArray(signature);
	}
}
