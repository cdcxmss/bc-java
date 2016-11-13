package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.pqc.crypto.xmss.XMSSOid;

import junit.framework.TestCase;

public class OidTest extends TestCase {

	public void testXMSSOidException1() {
		XMSSOid xmssOid = XMSSOid.lookup("SHA-256", 16, -1);
		assertEquals(xmssOid, null);
	}
	
	public void testXMSSOidException2() {
		XMSSOid xmssOid = XMSSOid.lookup("SHA-256", 16, 8);
		assertEquals(xmssOid, null);
	}
	
	public void testXMSSOidException3() {
		XMSSOid xmssOid = XMSSOid.lookup("SHA-256", 4, 10);
		assertEquals(xmssOid, null);
	}
	
	public void testXMSSOid() {
		XMSSOid xmssOid = XMSSOid.lookup("SHA-256", 16, 10);
		assertEquals(0x01000001, xmssOid.getOid());
		assertEquals("XMSS_SHA2-256_W16_H10", xmssOid.toString());
		xmssOid = XMSSOid.lookup("SHA-256", 16, 16);
		assertEquals(0x02000002, xmssOid.getOid());
		assertEquals("XMSS_SHA2-256_W16_H16", xmssOid.toString());
		xmssOid = XMSSOid.lookup("SHA-256", 16, 20);
		assertEquals(0x03000003, xmssOid.getOid());
		assertEquals("XMSS_SHA2-256_W16_H20", xmssOid.toString());
		xmssOid = XMSSOid.lookup("SHA-512", 16, 10);
		assertEquals(0x04000004, xmssOid.getOid());
		assertEquals("XMSS_SHA2-512_W16_H10", xmssOid.toString());
		xmssOid = XMSSOid.lookup("SHA-512", 16, 16);
		assertEquals(0x05000005, xmssOid.getOid());
		assertEquals("XMSS_SHA2-512_W16_H16", xmssOid.toString());
		xmssOid = XMSSOid.lookup("SHA-512", 16, 20);
		assertEquals(0x06000006, xmssOid.getOid());
		assertEquals("XMSS_SHA2-512_W16_H20", xmssOid.toString());
	}
}
