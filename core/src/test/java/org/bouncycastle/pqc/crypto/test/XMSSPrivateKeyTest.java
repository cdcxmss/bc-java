package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKey;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

import junit.framework.TestCase;

/**
 * Test cases for XMSSPrivateKey class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSPrivateKeyTest extends TestCase {

	public void testPrivateKeyParsing() {
		XMSSParameters params = new XMSSParameters(8, new SHA256Digest(), new NullPRNG());
		XMSS xmss = new XMSS(params);
		xmss.generateKeys();
		XMSSPrivateKey privateKey = xmss.getPrivateKey();
		privateKey.setIndex(0xaa);
		byte[] root = {
			(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
			(byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f,
			(byte) 0x10, (byte) 0x20, (byte) 0x30, (byte) 0x03, (byte) 0x40, (byte) 0x50, (byte) 0x60, (byte) 0x70,
			(byte) 0x80, (byte) 0x90, (byte) 0xa0, (byte) 0xb0, (byte) 0xc0, (byte) 0xd0, (byte) 0xe0, (byte) 0xf0
		};
		privateKey.setRoot(root);
		int expectedIndex = privateKey.getIndex();
		byte[] expectedSecretKeySeed = privateKey.getSecretKeySeed();
		byte[] expectedSecretKeyPRF = privateKey.getSecretKeyPRF();
		byte[] expectedPublicSeed = privateKey.getPublicSeed();
		byte[] expectedRoot = privateKey.getRoot();
		
		byte[][] export = privateKey.toByteArray();
		try {
			privateKey.parseByteArray(export);
		} catch (ParseException ex) {
			ex.printStackTrace();
		}
		assertEquals(expectedIndex, privateKey.getIndex());
		assertEquals(true, XMSSUtil.compareByteArray(expectedSecretKeySeed, privateKey.getSecretKeySeed()));
		assertEquals(true, XMSSUtil.compareByteArray(expectedSecretKeyPRF, privateKey.getSecretKeyPRF()));
		assertEquals(true, XMSSUtil.compareByteArray(expectedPublicSeed, privateKey.getPublicSeed()));
		assertEquals(true, XMSSUtil.compareByteArray(expectedRoot, privateKey.getRoot()));
	}
}
