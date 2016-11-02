package org.bouncycastle.pqc.crypto.test;

import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.pqc.crypto.xmss.KeyedHashFunction;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

/**
 * Test cases for XMSSUtil class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class KeyedHashFunctionTest extends TestCase {

	KeyedHashFunction khfSHA256;
	KeyedHashFunction khfSHA512;
	private byte[] key1;
	private byte[] key2;
	private byte[] key3;
	private byte[] key4;
	private byte[] key5;
	private byte[] key6;
	private byte[] addr1;
	private byte[] addr2;
	private byte[] addr3;
	
	public void setUp() {
		khfSHA256 = new KeyedHashFunction(new SHA256Digest());
		khfSHA512 = new KeyedHashFunction(new SHA512Digest());
		key1 = new byte[32];
		key2 = new byte[32];
		key3 = new byte[32];
		key4 = new byte[64];
		key5 = new byte[64];
		key6 = new byte[64];
		addr1 = new byte[32];
		addr2 = new byte[32];
		addr3 = new byte[32];
		Arrays.fill(key1, (byte) 0x00);
		Arrays.fill(key2, (byte) 0xff);
		Arrays.fill(key3, (byte) 0xab);
		Arrays.fill(key4, (byte) 0x00);
		Arrays.fill(key5, (byte) 0xff);
		Arrays.fill(key6, (byte) 0xab);
		Arrays.fill(addr1, (byte) 0x00);
		Arrays.fill(addr2, (byte) 0xff);
		Arrays.fill(addr3, (byte) 0xef);
	}
	
	public void testF() {

	}
	
	public void testH() {
		
	}
	
	public void testHMsg() {
		
	}
	
	public void testPRF() {
		// SHA256
		byte[] hash = khfSHA256.PRF(key1, addr1);
		assertEquals("6945a6f13aa83e598cb8d0abebb5cddbd87e576226517f9001c1d36bb320bf80", Hex.toHexString(hash));
		hash = khfSHA256.PRF(key2, addr2);
		assertEquals("741c361fb60c2b81592568f4e13dcefdb3d9954a3f329c563172e00fae5a1324", Hex.toHexString(hash));
		hash = khfSHA256.PRF(key3, addr3);
		assertEquals("29b2d5d1a163f60870f46e0def5dd66e6d5bd0eea7d83368b59d662cd11d422e", Hex.toHexString(hash));
		// SHA512
		hash = khfSHA512.PRF(key4, addr1);
		assertEquals("25fc9eb157c443b49dcaf5b76d21086c79dd06fa474fd2b1046bc975855484b9618a442b4f2377a549eaa657c4a2a0dc9b7ea329a93382ef777a2ed402c88973", Hex.toHexString(hash));
		hash = khfSHA512.PRF(key5, addr2);
		assertEquals("90504454416decc614415cc16839338fcbfdee590e85cff80e5d7175e71ec42734aa80ef8e9c7964b6bae4c45a9fea7e58a318b65f1cf389550344932664c492", Hex.toHexString(hash));
		hash = khfSHA512.PRF(key6, addr3);
		assertEquals("5b8d6e09e91a55db05fc762b70fac533e5aebd7d80b8b2ae1190dd205a0a5ff058874b6818b3ac804c7c9d1fa5580605a0229cfc6a00c519b15caadbd27e2ce0", Hex.toHexString(hash));
	}
}
