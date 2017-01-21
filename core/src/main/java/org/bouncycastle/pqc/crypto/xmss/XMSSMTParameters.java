package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS^MT Parameters.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 *
 */
public class XMSSMTParameters {
	
	private XMSSOidInterface oid;
	private XMSS xmss;
	private int height;
	private int layers;

	public XMSSMTParameters(int height, int layers, Digest digest, SecureRandom prng) {
		super();
		this.height = height;
		this.layers = layers;
		this.xmss = new XMSS(new XMSSParameters(xmssTreeHeight(height, layers), digest, prng));
		oid = XMSSMTOid.lookup(getDigest().getAlgorithmName(), getDigestSize(), getWinternitzParameter(), getLen(), getHeight(), layers);
		/*
		if (oid == null) {
			throw new InvalidParameterException();
		}
		*/
	}
	
	private static int xmssTreeHeight(int height, int layers) throws IllegalArgumentException {
		if (height < 2) {
			throw new IllegalArgumentException("totalHeight must be > 1");
		}
		if (height % layers != 0){
			throw new IllegalArgumentException("layers must divide totalHeight without remainder");
		}
		return height / layers;
	}

	public int getHeight() {
		return height;
	}
	
	public int getLayers() {
		return layers;
	}
	
	protected XMSS getXMSS() {
		return xmss;
	}
	
	protected WOTSPlus getWOTSPlus() {
		return xmss.getWOTSPlus();
	}
	
	protected Digest getDigest() {
		return xmss.getParams().getDigest();
	}
	
	protected int getDigestSize() {
		return xmss.getParams().getDigestSize();
	}
	
	protected int getWinternitzParameter() {
		return xmss.getParams().getWinternitzParameter();
	}
	
	protected int getLen() {
		return xmss.getWOTSPlus().getParams().getLen();
	}
}
