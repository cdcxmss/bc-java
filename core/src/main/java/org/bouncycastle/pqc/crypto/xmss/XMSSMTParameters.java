package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS Parameters for XMSS Mutli-Tree system
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 *
 */
public class XMSSMTParameters extends XMSSParameters{
	
	/**
	 * 
	 */
	private int totalHeight;
	
	/**
	 * The number of layers. This equals parameter d in the draft.
	 */
	private int layers;

	/**
	 * Constructor
	 * the totalHeight has to be divided by the number of layers without remainder
	 * @param layers the number of layers
	 * @param totalHeight the total height of the {@link XMSSMT}
	 * @param digest Digest to use
	 * @param prng PRNG
	 */
	public XMSSMTParameters(int layers, int totalHeight, Digest digest, SecureRandom prng) {
		super(XMSSTreeHeight(layers, totalHeight), digest, prng);
		this.layers = layers;
		this.totalHeight = totalHeight;
	}
	
	/**
	 * Calculate the height of the {@link XMSS} trees
	 * Total height has to be greater or equal to 2 and has to be divided by the number of layers without remainder.
	 * @param layers the number of layers
	 * @param totalHeight the total height of the {@link XMSSMT}
	 * @return the totalHeight divided by layers if it is greater or equal to 2 and divides without remainder otherwise an {@link IllegalArgumentException} is thrown
	 */
	private static int XMSSTreeHeight(int layers, int totalHeight){
		if (totalHeight < 2) {
			throw new IllegalArgumentException("totalHeight is less than 2");
		}
		if (totalHeight % layers != 0){
			throw new IllegalArgumentException("totalHeight has to be divided by layers without remainder");
		}
		return (int)(totalHeight / layers);
	}

	public int getTotalHeight() {
		return totalHeight;
	}

	public int getLayers() {
		return layers;
	}

}
