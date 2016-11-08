package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;

import junit.framework.TestCase;

/**
 * Test cases for XMSS class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSTest extends TestCase {

	public void testGenKeyPairSHA256() {
		XMSSParameters xmssParams = new XMSSParameters(8, new SHA256Digest(), new NullPRNG());
		XMSS xmss = new XMSS(xmssParams);
		xmss.genKeyPair();
		byte[] expected1 = {
			(byte)0xaa, (byte)0x0a, (byte)0x52, (byte)0xd3, (byte)0xaa, (byte)0xd7, (byte)0x64, (byte)0x68,
			(byte)0x6e, (byte)0x5c, (byte)0x49, (byte)0x38, (byte)0xc4, (byte)0x04, (byte)0x85, (byte)0x77,
			(byte)0x55, (byte)0x65, (byte)0x4d, (byte)0xa5, (byte)0x09, (byte)0x77, (byte)0x7c, (byte)0xda,
			(byte)0xe8, (byte)0x99, (byte)0xc7, (byte)0x1e, (byte)0x7d, (byte)0x46, (byte)0xa8, (byte)0x00
		};
		byte[] actual = xmss.getPublicKey().getRoot();
		for (int i = 0; i < expected1.length; i++) {
			assertEquals(expected1[i], actual[i]);
		}
		
		xmssParams = new XMSSParameters(7, new SHA256Digest(), new NullPRNG());
		xmss = new XMSS(xmssParams);
		xmss.genKeyPair();
		byte[] expected2 = {
			(byte)0x7f, (byte)0xad, (byte)0x5b, (byte)0xa8, (byte)0x41, (byte)0xc1, (byte)0x5a, (byte)0x54,
			(byte)0x2f, (byte)0x87, (byte)0xb3, (byte)0x62, (byte)0x14, (byte)0x69, (byte)0x8b, (byte)0xde,
			(byte)0x19, (byte)0x77, (byte)0xa5, (byte)0xce, (byte)0x4c, (byte)0x5c, (byte)0x6e, (byte)0xa0,
			(byte)0x0a, (byte)0xd8, (byte)0x69, (byte)0x36, (byte)0x4f, (byte)0xdc, (byte)0x75, (byte)0xa9
		};
		actual = xmss.getPublicKey().getRoot();
		for (int i = 0; i < expected2.length; i++) {
			assertEquals(expected2[i], actual[i]);
		}
	}
	
	public void testGenKeyPairSHA512() {
		XMSSParameters xmssParams = new XMSSParameters(8, new SHA512Digest(), new NullPRNG());
		XMSS xmss = new XMSS(xmssParams);
		xmss.genKeyPair();
		byte[] expected1 = {
			(byte)0xa4, (byte)0x71, (byte)0xd7, (byte)0x3b, (byte)0x6c, (byte)0x64, (byte)0x34, (byte)0xe1,
			(byte)0x9d, (byte)0xf7, (byte)0xaf, (byte)0xab, (byte)0xda, (byte)0xda, (byte)0x6c, (byte)0x11,
			(byte)0xa1, (byte)0x32, (byte)0x21, (byte)0x08, (byte)0xf8, (byte)0x65, (byte)0xdf, (byte)0x22,
			(byte)0xe4, (byte)0x0a, (byte)0xf7, (byte)0x0b, (byte)0xb7, (byte)0x8f, (byte)0x77, (byte)0x6b,
			(byte)0x69, (byte)0xf9, (byte)0x8a, (byte)0x7c, (byte)0xe4, (byte)0x1d, (byte)0x6a, (byte)0x97,
			(byte)0xda, (byte)0x26, (byte)0xd1, (byte)0xab, (byte)0x88, (byte)0x00, (byte)0xce, (byte)0x67,
			(byte)0xf6, (byte)0xbb, (byte)0x64, (byte)0xad, (byte)0x6d, (byte)0xce, (byte)0x97, (byte)0xc1,
			(byte)0xe7, (byte)0x2a, (byte)0x4f, (byte)0x83, (byte)0xf8, (byte)0x19, (byte)0xac, (byte)0xa6
		};
		byte[] actual = xmss.getPublicKey().getRoot();
		for (int i = 0; i < expected1.length; i++) {
			assertEquals(expected1[i], actual[i]);
		}
		
		xmssParams = new XMSSParameters(7, new SHA512Digest(), new NullPRNG());
		xmss = new XMSS(xmssParams);
		xmss.genKeyPair();
		byte[] expected2 = {
			(byte)0x6e, (byte)0x35, (byte)0xde, (byte)0x56, (byte)0x0b, (byte)0xf1, (byte)0x6d, (byte)0xf3,
			(byte)0x94, (byte)0xce, (byte)0x16, (byte)0x6d, (byte)0xbb, (byte)0xc1, (byte)0x7f, (byte)0xd9,
			(byte)0x32, (byte)0xd5, (byte)0xe5, (byte)0xd7, (byte)0x9b, (byte)0x33, (byte)0xc8, (byte)0x9e,
			(byte)0x38, (byte)0x63, (byte)0x4e, (byte)0x2d, (byte)0x9f, (byte)0xfa, (byte)0xa5, (byte)0x86,
			(byte)0x6c, (byte)0xca, (byte)0x65, (byte)0xe3, (byte)0xad, (byte)0x8f, (byte)0x44, (byte)0xcb,
			(byte)0x74, (byte)0x8f, (byte)0xdc, (byte)0x05, (byte)0x98, (byte)0x48, (byte)0x73, (byte)0x87,
			(byte)0x61, (byte)0x81, (byte)0x07, (byte)0xac, (byte)0x6e, (byte)0x77, (byte)0x92, (byte)0x38,
			(byte)0x3d, (byte)0x8f, (byte)0x89, (byte)0xca, (byte)0xdb, (byte)0x30, (byte)0x2e, (byte)0xe4
		};
		actual = xmss.getPublicKey().getRoot();
		for (int i = 0; i < expected2.length; i++) {
			assertEquals(expected2[i], actual[i]);
		}
	}
}
