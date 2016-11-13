package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.Digest;

/**
 * XMSS Parameters for XMSS Mutli-Tree system
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 *
 */
public class XMSSMTParameters extends XMSSParameters{
	
	private int totalHeight;
	
	private int layers;

	/**
	 * Construcor
	 * the totalHeight has to be divided by the number of layers without remainder
	 * @param layers the number of layers
	 * @param totalHeight the total height of the {@link XMSSMT}
	 * @param digest Digest to use
	 * @param prng PRNG
	 */
	public XMSSMTParameters(int layers, int totalHeight, Digest digest, int winternitzParameter) {
		super(requirementCheck(layers, totalHeight), digest, winternitzParameter);
		this.layers = layers;
		this.totalHeight = totalHeight;
	}
	
	/**
	 * Checks the requirement that the totalHeight has to be divided by the number of layers without remainder
	 * @param layers the number of layers
	 * @param totalHeight the total height of the {@link XMSSMT}
	 * @return the totalHeight divided by layers if it divides without remainder otherwise an {@link IllegalArgumentException} is thrown
	 */
	private static int requirementCheck(int layers, int totalHeight){
		if (totalHeight % layers != 0){
			throw new IllegalArgumentException("totalHeight has to be divided by layers without remainder");
		}
		return (int)(totalHeight / layers);
	}

}
