package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS^MT Parameters.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 *
 */
public class XMSSMTParameters extends XMSSParameters {
	
	private XMSSOidInterface oid;
	private int totalHeight;
	private int layers;

	public XMSSMTParameters(int totalHeight, int layers, Digest digest, SecureRandom prng) {
		super(XMSSTreeHeight(totalHeight, layers), digest, prng);
		this.layers = layers;
		this.totalHeight = totalHeight;
		oid = XMSSMTOid.lookup(getDigest().getAlgorithmName(), getDigestSize(), getWinternitzParameter(), getWOTSPlus().getParams().getLen(), totalHeight, layers);
		/*
		if (oid == null) {
			throw new InvalidParameterException();
		}
		*/
	}
	
	private static int XMSSTreeHeight(int totalHeight, int layers) throws IllegalArgumentException {
		if (totalHeight < 2) {
			throw new IllegalArgumentException("totalHeight must be > 1");
		}
		if (totalHeight % layers != 0){
			throw new IllegalArgumentException("layers must divide totalHeight without remainder");
		}
		return totalHeight / layers;
	}

	public XMSSOidInterface getOid() {
		return oid;
	}
	
	public int getTotalHeight() {
		return totalHeight;
	}
	
	public int getLayers() {
		return layers;
	}
}
