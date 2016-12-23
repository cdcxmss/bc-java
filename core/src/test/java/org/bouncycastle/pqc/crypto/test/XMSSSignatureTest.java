package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSignature;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

import junit.framework.TestCase;

/**
 * Test cases for XMSSSignature class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSSignatureTest extends TestCase {

	public void testSignatureParsingSHA256() {
		XMSSParameters params = new XMSSParameters(10, new SHA256Digest(), new NullPRNG());
		XMSS xmss = new XMSS(params);
		xmss.generateKeys();
		byte[] message = new byte[1024];
		byte[] sig1 = xmss.signMT(message);
		XMSSSignature sig2 = new XMSSSignature(xmss);
		try {
			sig2.parseByteArray(sig1);
		} catch (ParseException ex) {
			ex.printStackTrace();
			fail();
		}
		byte[] sig3 = sig2.toByteArray();
		assertEquals(true, XMSSUtil.compareByteArray(sig1, sig3));
	}
	
	public void testSignatureParsingSHA512() {
		XMSSParameters params = new XMSSParameters(10, new SHA512Digest(), new NullPRNG());
		XMSS xmss = new XMSS(params);
		xmss.generateKeys();
		byte[] message = new byte[1024];
		byte[] sig1 = xmss.signMT(message);
		XMSSSignature sig2 = new XMSSSignature(xmss);
		try {
			sig2.parseByteArray(sig1);
		} catch (ParseException ex) {
			ex.printStackTrace();
			fail();
		}
		byte[] sig3 = sig2.toByteArray();
		assertEquals(true, XMSSUtil.compareByteArray(sig1, sig3));
	}
}
