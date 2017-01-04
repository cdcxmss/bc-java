package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature;
import org.bouncycastle.pqc.crypto.xmss.XMSSSignature;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * Test cases for XMSSSignature class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSMTSignatureTest extends TestCase {

	public void testSignatureParsingSHA256() {
		int totalHeight = 20;
		int layers = 2;
		XMSSMTParameters params = new XMSSMTParameters(layers, totalHeight, new SHA256Digest(), new NullPRNG());
		XMSSMT xmssMt = new XMSSMT(params);
		xmssMt.generateKeys();
		byte[] message = new byte[1024];
		byte[] sig1 = xmssMt.signMT(message);
		XMSSMTSignature sig2 = new XMSSMTSignature(params);
		try {
			sig2.parseByteArray(sig1);
		} catch (ParseException ex) {
			ex.printStackTrace();
			fail();
		}
		byte[] sig3 = sig2.toByteArray();
		assertEquals(true, Arrays.areEqual(sig1, sig3));
	}
	
	public void testSignatureParsingSHA512() {
		int totalHeight = 20;
		int layers = 2;
		XMSSMTParameters params = new XMSSMTParameters(layers, totalHeight, new SHA512Digest(), new NullPRNG());
		XMSSMT xmssMt = new XMSSMT(params);
		xmssMt.generateKeys();
		byte[] message = new byte[1024];
		byte[] sig1 = xmssMt.signMT(message);
		XMSSMTSignature sig2 = new XMSSMTSignature(params);
		try {
			sig2.parseByteArray(sig1);
		} catch (ParseException ex) {
			ex.printStackTrace();
			fail();
		}
		byte[] sig3 = sig2.toByteArray();
		assertEquals(true, Arrays.areEqual(sig1, sig3));
	}
}
