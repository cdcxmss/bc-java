package org.bouncycastle.pqc.crypto.xmss;

import java.security.InvalidParameterException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS Parameters.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSParameters {

	private XMSSOid oid;
	private Digest digest;
	private SecureRandom prng;
	private int digestSize;
	private int winternitzParameter;
	private int height;
	private WOTSPlus wotsPlus;

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
		this.digest = digest;
		this.prng = prng;
		digestSize = XMSSUtil.getDigestSize(digest);
		winternitzParameter = 16;
		this.height = height;
		wotsPlus = new WOTSPlus(new WOTSPlusParameters(digest));
		XMSSOid oid = XMSSOid.lookup(digest.getAlgorithmName(), digestSize, winternitzParameter, wotsPlus.getParams().getLen(), height);
		if (oid == null) {
			throw new InvalidParameterException();
		}
		this.oid = oid;
	}
	
	public XMSSOid getOid() {
		return oid;
	}

	public Digest getDigest() {
		return digest;
	}
	
	public SecureRandom getPRNG() {
		return prng;
	}
	
	public int getDigestSize() {
		return digestSize;
	}
	
	public int getWinternitzParameter() {
		return winternitzParameter;
	}
	
	public int getHeight() {
		return height;
	}
	
	public WOTSPlus getWOTSPlus() {
		return wotsPlus;
	}
}
