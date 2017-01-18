package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKey;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * Test cases for XMSSPublicKey class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSMTPublicKeyTest extends TestCase {

	public void testPublicKeyParsingSHA256() {
		int totalHeight = 20;
		int layers = 2;
		byte[] publicKeyBytes = {
				(byte)0x7c, (byte)0x6e, (byte)0xc0, (byte)0xfc, (byte)0x96, (byte)0x8e, (byte)0x88, (byte)0xe1, (byte)0xe5, (byte)0xaf, (byte)0x65, (byte)0xb9, (byte)0x35, 
				(byte)0x61, (byte)0x98, (byte)0x8d, (byte)0x9f, (byte)0xc5, (byte)0x5f, (byte)0xa6, (byte)0x0b, (byte)0x5a, (byte)0x44, (byte)0x4c, (byte)0x45, (byte)0x18, 
				(byte)0x39, (byte)0xa9, (byte)0xdf, (byte)0x74, (byte)0xe4, (byte)0xd4, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
				(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
				(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
		};
		
		XMSSMTParameters params = new XMSSMTParameters(totalHeight, layers, new SHA256Digest(), new NullPRNG());
		XMSSMTPublicKey publicKey = new XMSSMTPublicKey(params);
		try {
			publicKey.parseByteArray(publicKeyBytes);
			byte[] export = publicKey.toByteArray();
			assertTrue(Arrays.areEqual(publicKeyBytes, export));
		} catch (ParseException e) {
			e.printStackTrace();
			fail();
		}
	}
}
