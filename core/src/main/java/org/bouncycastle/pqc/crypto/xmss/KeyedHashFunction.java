package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

/**
 * Crypto related functions for XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class KeyedHashFunction {

	Digest digest;
	
	public KeyedHashFunction(Digest digest) {
		super();
		this.digest = digest;
	}
	
	private byte[] coreDigest(int fixedValue, byte[] key, byte[] addr) {
		if (addr.length != 32) {
			throw new IllegalArgumentException("addr needs to be 32 byte");
		}
		int n = digest.getDigestSize();	// 32 / 64 byte
		if (key.length != n && key.length != 3*n) {
			throw new IllegalArgumentException("key size not valid");
		}
		byte[] buffer = new byte[(2 * n) + 32];
		byte[] in = XMSSUtil.intToBytesBigEndian(fixedValue, n);
		// fill first n byte of out buffer
		for (int i = 0; i < in.length; i++) {
			buffer[i] = in[i];
		}
		// add key
		for (int i = 0; i < key.length; i++) {
			buffer[in.length + i] = key[i];
		}
		// add addr
		for (int i = 0; i < addr.length; i++) {
			buffer[in.length + key.length + i] = addr[i];
		}
		digest.update(buffer, 0, buffer.length);
		byte[] out = new byte[n];
		digest.doFinal(out, 0);
		return out;
	}
	
	public byte[] F(byte[] key, byte[] addr) {
		return coreDigest(0, key, addr);
	}
	
	public byte[] H(byte[] key, byte[] addr) {
		return coreDigest(1, key, addr);
	}
	
	public byte[] HMsg(byte[] key, byte[] addr) {
		return coreDigest(2, key, addr);
	}
	
	public byte[] PRF(byte[] seed, byte[] addr) {
		return coreDigest(3, seed, addr);
	}
}
