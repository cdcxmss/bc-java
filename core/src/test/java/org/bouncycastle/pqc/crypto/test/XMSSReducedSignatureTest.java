package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.XMSSMT;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

/**
 * Test cases for XMSSReducedSignature class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSReducedSignatureTest extends TestCase {

	public void testSignatureParsingSHA256() {
		XMSSMTParameters params = new XMSSMTParameters(8, 2, new SHA256Digest(), new NullPRNG());
		XMSSMT mt = new XMSSMT(params);
		mt.generateKeys();
		byte[] message = new byte[1024];
		byte[] sig1 = mt.sign(message);
		XMSSMTSignature sig2 = new XMSSMTSignature(params);
		try {
			sig2.parseByteArray(sig1);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		XMSSReducedSignature reducedSignature1 = sig2.getReducedSignatures().get(0);
		byte[] reducedSignatureBinary = reducedSignature1.toByteArray();
		XMSSReducedSignature reducedSignature2 = new XMSSReducedSignature(params);
		try {
			reducedSignature2.parseByteArray(reducedSignatureBinary);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		assertTrue(XMSSUtil.compareByteArray(reducedSignatureBinary, reducedSignature2.toByteArray()));
	}
		
	public void testSignatureParsingSHA512() {
		XMSSMTParameters params = new XMSSMTParameters(4, 2, new SHA512Digest(), new NullPRNG());
		XMSSMT mt = new XMSSMT(params);
		mt.generateKeys();
		byte[] message = new byte[1024];
		byte[] sig1 = mt.sign(message);
		XMSSMTSignature sig2 = new XMSSMTSignature(params);
		try {
			sig2.parseByteArray(sig1);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		XMSSReducedSignature reducedSignature1 = sig2.getReducedSignatures().get(0);
		byte[] reducedSignatureBinary = reducedSignature1.toByteArray();
		XMSSReducedSignature reducedSignature2 = new XMSSReducedSignature(params);
		try {
			reducedSignature2.parseByteArray(reducedSignatureBinary);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		assertTrue(XMSSUtil.compareByteArray(reducedSignatureBinary, reducedSignature2.toByteArray()));
	}
	
	public void testConstructor() {
		XMSSMTParameters params = new XMSSMTParameters(20, 10, new SHA512Digest(), new NullPRNG());
		XMSSReducedSignature sig = new XMSSReducedSignature(params);
		byte[] sigByte = sig.toByteArray();
		/* check everything is 0 */
		for (int i = 0; i < sigByte.length; i++) {
			assertEquals(0x00, sigByte[i]);
		}
	}
}
