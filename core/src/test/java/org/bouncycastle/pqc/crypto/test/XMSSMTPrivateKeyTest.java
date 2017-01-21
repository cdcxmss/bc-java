package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKey;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

import junit.framework.TestCase;

/**
 * Test cases for XMSSPrivateKey class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMTPrivateKeyTest extends TestCase {

	public void testPrivateKeyParsingSHA256() {
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
		assertTrue(XMSSUtil.compareByteArray(privateKey, mt.getPrivateKey()));
	}
	
	public void testIncrementIndex() {
		XMSSMTParameters params = new XMSSMTParameters(20, 10, new SHA256Digest(), new NullPRNG());
		XMSSMT mt = new XMSSMT(params);
		mt.generateKeys();
		byte[] privateKeyBin = mt.getPrivateKey();
		byte[] publicKeyBin = mt.getPublicKey();
		XMSSMTPrivateKey privateKey = new XMSSMTPrivateKey(params);
		try {
			privateKey.parseByteArray(privateKeyBin);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		ZonedDateTime fakedTime = ZonedDateTime.now(ZoneOffset.UTC);
		fakedTime = fakedTime.minusHours(2);
		privateKey.setLastUsage(fakedTime);
		byte[] privateKeyBinMinusTwoHours = privateKey.toByteArray();
		try {
			mt.importKeys(privateKeyBinMinusTwoHours, publicKeyBin);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		/* as key is 2 hours old index will be increased by 500, signature then has index 500 and next private key index 501 */
		byte[] signature = mt.sign(new byte[1024]);
		assertEquals((byte)0x00, signature[0]);
		assertEquals((byte)0x01, signature[1]);
		assertEquals((byte)0xf4, signature[2]);
		assertEquals((byte)0x00, mt.getPrivateKey()[0]);
		assertEquals((byte)0x01, mt.getPrivateKey()[1]);
		assertEquals((byte)0xf5, mt.getPrivateKey()[2]);
	}
}
