package org.bouncycastle.pqc.crypto.xmss;

import java.security.InvalidParameterException;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS Parameters.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSParameters {

	private XMSSOid oid;
	private int height;
	private Digest digest;
	private int digestSize;
	private int winternitzParameter;
	
	/**
	 * XMSS Constructor...
	 * @param height Height of tree.
	 * @param digest Digest to use.
	 * @param winternitzParameter Winternitz parameter.
	 */
	public XMSSParameters(int height, Digest digest, int winternitzParameter) {
		super();
		if (digest == null) {
			throw new NullPointerException("digest == null");
		}
		XMSSOid oid = XMSSOid.lookup(digest.getAlgorithmName(), winternitzParameter, height);
		if (oid == null) {
			throw new InvalidParameterException();
		}
		this.oid = oid;
		this.height = height;
		this.digest = digest;
		this.digestSize = digest.getDigestSize();
		this.winternitzParameter = winternitzParameter;
	}
	
	public XMSSOid getOid() {
		return oid;
	}

	public int getHeight() {
		return height;
	}

	public Digest getDigest() {
		return digest;
	}
	
	public int getDigestSize() {
		return digestSize;
	}

	public int getWinternitzParameter() {
		return winternitzParameter;
	}
}
