package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * Test cases for XMSS^MT signature class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMTSignatureTest extends TestCase {

	public void testSignatureParsingSHA256() {
		int totalHeight = 6;
		int layers = 3;
		byte[] message = new byte[1024];
		XMSSMTParameters params = new XMSSMTParameters(totalHeight, layers, new SHA256Digest(), new NullPRNG());
		XMSSMT xmssMT = new XMSSMT(params);
		xmssMT.generateKeys();
		byte[] signature1 = xmssMT.sign(message);
		XMSSMTSignature mtSignature = new XMSSMTSignature(params);
		try {
			mtSignature.parseByteArray(signature1);
			byte[] signature2 = mtSignature.toByteArray();
			assertTrue(Arrays.areEqual(signature1, signature2));
		} catch (ParseException e) {
			e.printStackTrace();
			fail();
		}
	}
}
