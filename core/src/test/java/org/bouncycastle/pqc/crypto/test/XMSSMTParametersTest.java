package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.junit.Test;

import junit.framework.TestCase;

/**
 * Test cases for XMSSMTParameters class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSMTParametersTest extends TestCase{
	
	public void testParameterConstructionMinimum(){
		int totalHeight = 2;
		int layers = 2;
		SHA256Digest sha256 = new SHA256Digest();
		XMSSMTParameters params = new XMSSMTParameters(layers, totalHeight, sha256, new NullPRNG());
		assertEquals(2, params.getLayers());
		assertEquals(2, params.getTotalHeight());
		assertEquals(1, params.getHeight());
		assertEquals(sha256.getDigestSize(), params.getDigestSize());
		//we set the Winternitz parameter to 16.
		assertEquals(16, params.getWinternitzParameter());
	}
	
//	@Test(expected = IllegalArgumentException.class)
//	public void testParameterConstructionTotalTreeHeightDividedByLayersWithoutRemainder(){
//		int totalHeight = 5;
//		int layers = 3;
//		XMSSMTParameters params = new XMSSMTParameters(layers, totalHeight,  new SHA256Digest(), new NullPRNG());
//	}
//	
//	@Test(expected = IllegalArgumentException.class)
//	public void testParameterConstructionTotalTreeHeightLessThan2(){
//		int totalHeight = 1;
//		int layers = 1;
//		XMSSMTParameters params = new XMSSMTParameters(layers, totalHeight,  new SHA256Digest(), new NullPRNG());
//	}

}
