package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKey;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

import junit.framework.TestCase;

/**
 * Test cases for XMSSPublicKey class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMTPublicKeyTest extends TestCase {

	public void testPublicKeyParsingSHA256() {
		XMSSMTParameters params = new XMSSMTParameters(20, 10, new SHA256Digest(), new NullPRNG());
		XMSSMT mt = new XMSSMT(params);
		mt.generateKeys();
		byte[] privateKey = mt.getPrivateKey();
		byte[] publicKey = mt.getPublicKey();
		try {
			mt.importKeys(privateKey, publicKey);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		assertTrue(XMSSUtil.compareByteArray(publicKey, mt.getPublicKey()));
	}
	
	public void testConstructor() {
		XMSSMTParameters params = new XMSSMTParameters(20, 10, new SHA256Digest(), new NullPRNG());
		XMSSMTPublicKey pk = new XMSSMTPublicKey(params);
		byte[] pkByte = pk.toByteArray();
		/* check everything is 0 */
		for (int i = 0; i < pkByte.length; i++) {
			assertEquals(0x00, pkByte[i]);
		}
	}
}
