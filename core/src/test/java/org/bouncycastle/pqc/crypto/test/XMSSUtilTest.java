package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

import junit.framework.TestCase;

/**
 * Test cases for XMSSUtil class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSUtilTest extends TestCase {

	public void testLog2() {
		assertEquals(3, XMSSUtil.log2(8));
		assertEquals(3, XMSSUtil.log2(10));
		assertEquals(26, XMSSUtil.log2(100010124));
	}
	
	public void testIntToBytesBigEndianException() {
		try {
			XMSSUtil.intToBytesBigEndian(1, 3);
			fail();
		} catch (Exception e) { }
	}
	
	public void testIntToBytesBigEndian() {
		byte[] b = XMSSUtil.intToBytesBigEndian(1, 4);
		assertEquals(4, b.length);
		assertEquals((byte) 0, b[0]);
		assertEquals((byte) 0, b[1]);
		assertEquals((byte) 0, b[2]);
		assertEquals((byte) 1, b[3]);
		b = XMSSUtil.intToBytesBigEndian(1, 6);
		assertEquals(6, b.length);
		assertEquals((byte) 0, b[0]);
		assertEquals((byte) 0, b[1]);
		assertEquals((byte) 0, b[2]);
		assertEquals((byte) 0, b[3]);
		assertEquals((byte) 0, b[4]);
		assertEquals((byte) 1, b[5]);
		b = XMSSUtil.intToBytesBigEndian(1, 32);
		for (int i = 0; i < 31; i++) {
			assertEquals((byte) 0, b[i]);
		}
		assertEquals((byte) 1, b[31]);
	}
}
