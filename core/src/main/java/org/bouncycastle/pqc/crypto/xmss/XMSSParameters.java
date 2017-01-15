package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS Parameters.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSParameters {

	private XMSSOid oid;
	private WOTSPlus wotsPlus;
	private SecureRandom prng;
	private int height;

	/**
	 * XMSS Constructor...
	 * @param height Height of tree.
	 * @param digest Digest to use.
	 * @param winternitzParameter Winternitz parameter.
	 */
	public XMSSParameters(int height, Digest digest, SecureRandom prng) {
		super();
		if (digest == null) {
			throw new NullPointerException("digest == null");
		}
		if (prng == null) {
			throw new NullPointerException("prng == null");
		}
		wotsPlus = new WOTSPlus(new WOTSPlusParameters(digest));
		this.prng = prng;
		this.height = height;
		XMSSOid oid = XMSSOid.lookup(getDigest().getAlgorithmName(), getDigestSize(), getWinternitzParameter(), wotsPlus.getParams().getLen(), height);
		/* TODO: XMSS single variant params are incompatible to those in XMSS^MT
		if (oid == null) {
			throw new InvalidParameterException();
		}
		*/
		this.oid = oid;
	}
	
	public XMSSOid getOid() {
		return oid;
	}

	public Digest getDigest() {
		return wotsPlus.getParams().getDigest();
	}
	
	public SecureRandom getPRNG() {
		return prng;
	}
	
	public int getDigestSize() {
		return wotsPlus.getParams().getDigestSize();
	}
	
	public int getWinternitzParameter() {
		return wotsPlus.getParams().getWinternitzParameter();
	}
	
	public int getHeight() {
		return height;
	}
	
	public WOTSPlus getWOTSPlus() {
		return wotsPlus;
	}
}
