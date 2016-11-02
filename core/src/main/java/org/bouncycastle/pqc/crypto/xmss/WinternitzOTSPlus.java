package org.bouncycastle.pqc.crypto.xmss;

/**
 * This class implements the WOTS+ one-time signature system
 * as described in draft-irtf-cfrg-xmss-hash-based-signatures-06.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class WinternitzOTSPlus {

	/**
	 * The WOTS+ parameters
	 */
	private WinternitzOTSPlusParameters params;

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
	}
}
