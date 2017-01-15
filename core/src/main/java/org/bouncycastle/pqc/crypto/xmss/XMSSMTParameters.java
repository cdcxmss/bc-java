package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS Parameters for XMSS Mutli-Tree system
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 *
 */
public class XMSSMTParameters extends XMSSParameters {
	
	private int totalHeight;
	private int layers;

	public XMSSMTParameters(int layers, int totalHeight, Digest digest, SecureRandom prng) {
		super(XMSSTreeHeight(layers, totalHeight), digest, prng);
		this.layers = layers;
		this.totalHeight = totalHeight;
	}
	
	private static int XMSSTreeHeight(int layers, int totalHeight) throws IllegalArgumentException {
		if (totalHeight < 2) {
			throw new IllegalArgumentException("totalHeight must be > 1");
		}
		if (totalHeight % layers != 0){
			throw new IllegalArgumentException("totalHeight has to be divided by layers without remainder");
		}
		return totalHeight / layers;
	}

	public int getTotalHeight() {
		return totalHeight;
	}

	public int getLayers() {
		return layers;
	}
}
