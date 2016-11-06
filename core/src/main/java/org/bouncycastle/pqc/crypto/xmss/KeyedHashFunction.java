package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;

/**
 * Crypto related functions for XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class KeyedHashFunction {

	Digest digest;
	
	public KeyedHashFunction(Digest digest) {
		super();
		this.digest = digest;
	}
	
	private byte[] coreDigest(int fixedValue, byte[] key, byte[] index) {
		int n = digest.getDigestSize();	// 32 / 64 byte
		byte[] buffer = new byte[(2 * n) + index.length];
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
	
	public byte[] H(byte[] key, XMSSAddress index) {
		if (index == null) {
			throw new NullPointerException("index == null");
		}
		byte[] address = index.toByteArray();
		return coreDigest(1, key, address);
	}
	
	public byte[] HMsg(byte[] key, XMSSAddress index) {
		if (index == null) {
			throw new NullPointerException("index == null");
		}
		byte[] address = index.toByteArray();
		return coreDigest(2, key, address);
	}
	
	public byte[] PRF(byte[] key, XMSSAddress index) {
		int n = digest.getDigestSize();
		if (key.length != n) {
			throw new IllegalArgumentException("wrong key length");
		}
		if (index == null) {
			throw new NullPointerException("index == null");
		}
		byte[] address = index.toByteArray();
		return coreDigest(3, key, address);
	}
}
