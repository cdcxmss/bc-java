package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKey;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

import junit.framework.TestCase;

/**
 * Test cases for XMSSPublicKey class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSPublicKeyTest extends TestCase {

	public void testPublicKeyParsing() {
		XMSSParameters params = new XMSSParameters(8, new SHA256Digest(), new NullPRNG());
		XMSS xmss = new XMSS(params);
		xmss.generateKeys();
		XMSSPublicKey publicKey = xmss.getPublicKey();
		publicKey.setOid(0x01);
		byte[] root = {
			(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
			(byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f,
			(byte) 0x10, (byte) 0x20, (byte) 0x30, (byte) 0x03, (byte) 0x40, (byte) 0x50, (byte) 0x60, (byte) 0x70,
			(byte) 0x80, (byte) 0x90, (byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0, (byte) 0xf0
		};
		publicKey.setRoot(root);
		byte[] export = publicKey.toByteArray();
		
		XMSSPublicKey publicKey2 = new XMSSPublicKey(xmss);
		try {
			publicKey2.parseByteArray(export);
		} catch (ParseException ex) {
			ex.printStackTrace();
			fail();
		}
		assertEquals(publicKey.getOid(), publicKey2.getOid());
		assertEquals(true, XMSSUtil.compareByteArray(publicKey.getRoot(), publicKey2.getRoot()));
		assertEquals(true, XMSSUtil.compareByteArray(publicKey.getPublicSeed(), publicKey2.getPublicSeed()));
	}
}
