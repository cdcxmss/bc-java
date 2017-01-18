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
	private int layers;
	private int totalHeight;

	public XMSSMTParameters(int layers, int totalHeight, Digest digest, SecureRandom prng) {
		super(XMSSTreeHeight(layers, totalHeight), digest, prng);
		this.layers = layers;
		this.totalHeight = totalHeight;
		oid = XMSSMTOid.lookup(getDigest().getAlgorithmName(), getDigestSize(), getWinternitzParameter(), getWOTSPlus().getParams().getLen(), totalHeight, layers);
		/*
		if (oid == null) {
			throw new InvalidParameterException();
		}
		*/
	}
	
	private static int XMSSTreeHeight(int layers, int totalHeight) throws IllegalArgumentException {
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
	
	public int getLayers() {
		return layers;
	}

	public int getTotalHeight() {
		return totalHeight;
	}
}
