package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.WOTSPlusParameters;

import junit.framework.TestCase;

/**
 * Test cases for WinternitzOTSPlusParameters class.
 *  
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class WOTSPlusParametersTest extends TestCase {
/*
	public void testConstructorException() {
		try {
			WOTSPlusParameters params = new WOTSPlusParameters(new SHA1Digest());
			fail();
		} catch (Exception ex) { }
	}
	
	public void testSHA256Len() {
		WOTSPlusParameters params = new WOTSPlusParameters(new SHA256Digest());
		assertEquals(32, params.getDigestSize());
		assertEquals(16, params.getWinternitzParameter());
		assertEquals(67, params.getLen());
	}
	
	public void testSHA512Len() {
		WOTSPlusParameters params = new WOTSPlusParameters(new SHA512Digest());
		assertEquals(64, params.getDigestSize());
		assertEquals(16, params.getWinternitzParameter());
		assertEquals(131, params.getLen());
	}
*/
}
