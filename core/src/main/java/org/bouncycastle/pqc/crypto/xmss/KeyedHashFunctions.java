package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

/**
 * Crypto related functions for XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class KeyedHashFunctions {

	private Digest digest;
	
	public KeyedHashFunctions(Digest digest) {
		super();
		if (digest == null) {
			throw new NullPointerException("digest == null");
		}
		this.digest = digest;
	}
	
	private byte[] coreDigest(int fixedValue, byte[] key, byte[] index) {
		int n = digest.getDigestSize();
		byte[] buffer = new byte[n + key.length + index.length];
		byte[] in = XMSSUtil.toBytesBigEndian(fixedValue, n);
		// fill first n byte of out buffer
		for (int i = 0; i < in.length; i++) {
			buffer[i] = in[i];
		}
		// add key
		for (int i = 0; i < key.length; i++) {
			buffer[in.length + i] = key[i];
		}
		// add index
		for (int i = 0; i < index.length; i++) {
			buffer[in.length + key.length + i] = index[i];
		}
		digest.update(buffer, 0, buffer.length);
		byte[] out = new byte[n];
		digest.doFinal(out, 0);
		return out;
	}
	
	public byte[] F(byte[] key, byte[] in) {
		int n = digest.getDigestSize();
		if (key.length != n) {
			throw new IllegalArgumentException("wrong key length");
		}
		if (in.length != n) {
			throw new IllegalArgumentException("wrong in length");
		}
		return coreDigest(0, key, in);
	}
	
	public byte[] H(byte[] key, byte[] in) {
		int n = digest.getDigestSize();
		if (key.length != n) {
			throw new IllegalArgumentException("wrong key length");
		}
		if (in.length != (2 * n)) {
			throw new IllegalArgumentException("wrong in length");
		}
		return coreDigest(1, key, in);
	}
	
	public byte[] HMsg(byte[] key, byte[] in) {
		int n = digest.getDigestSize();
		if (key.length != (3 * n)) {
			throw new IllegalArgumentException("wrong key length");
		}
		return coreDigest(2, key, in);
	}
	
	public byte[] PRF(byte[] key, byte[] address) {
		int n = digest.getDigestSize();
		if (key.length != n) {
			throw new IllegalArgumentException("wrong key length");
		}
		if (address.length != 32) {
			throw new IllegalArgumentException("wrong address length");
		}
		return coreDigest(3, key, address);
	}
}
