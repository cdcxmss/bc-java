package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.WinternitzOTSPlusParameters;

import junit.framework.TestCase;

/**
 * Test cases for WinternitzOTSPlusParameters class.
 *  
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class WinternitzOTSPlusParametersTest extends TestCase {

	public void testConstructorException() {
		try {
			WinternitzOTSPlusParameters params = new WinternitzOTSPlusParameters(new SHA1Digest(), new NullPRNG());
			fail();
		} catch (Exception ex) { }
	}
	
	public void testSHA256Len() {
		WinternitzOTSPlusParameters params = new WinternitzOTSPlusParameters(new SHA256Digest(), new NullPRNG());
		assertEquals(32, params.getDigestSize());
		assertEquals(16, params.getWinternitzParameter());
		assertEquals(67, params.getLen());
	}
	
	public void testSHA512Len() {
		WinternitzOTSPlusParameters params = new WinternitzOTSPlusParameters(new SHA512Digest(), new NullPRNG());
		assertEquals(64, params.getDigestSize());
		assertEquals(16, params.getWinternitzParameter());
		assertEquals(131, params.getLen());
	}
}
