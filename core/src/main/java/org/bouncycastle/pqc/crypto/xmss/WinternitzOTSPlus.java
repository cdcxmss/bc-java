package org.bouncycastle.pqc.crypto.xmss;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * This class implements the WOTS+ one-time signature system
 * as described in draft-irtf-cfrg-xmss-hash-based-signatures-06.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class WinternitzOTSPlus {

	/**
	 * WOTS+ parameters.
	 */
	private WinternitzOTSPlusParameters params;
	
	/**
	 * Keyed Hash Function
	 */
	private KeyedHashFunction khf;
	
	/**
	 * WOTS+ private key.
	 */
	private byte[][] privateKey;
	
	/**
	 * WOTS+ public key.
	 */
	private byte[][] publicKey;
	
	/**
	 * Public Seed.
	 */
	private byte[] publicSeed;
	
	/**
	 * Constructs a new WOTS+ one-time signature system based
	 * on the given WOTS+ parameters.
	 */
	public WinternitzOTSPlus(WinternitzOTSPlusParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		khf = new KeyedHashFunction(params.getDigest());
		int len = params.getLen();
		int n = params.getDigestSize();
		privateKey = new byte[len][n];
		publicKey = new byte[len][n];
		publicSeed = new byte[n];
	}
	
	public void genKeyPair() {
		genPrivateKey();
		genPublicKey();
	}
	
	private void genPrivateKey() {
		for (int i = 0; i < params.getLen(); i++) {
			params.getPRNG().nextBytes(privateKey[i]);
		}
	}
	
	private void genPublicKey() {
		params.getPRNG().nextBytes(publicSeed);

		OTSHashAddress address = new OTSHashAddress();
		for (int i = 0; i < params.getLen(); i++) {
			address.setChainAddress(i);
			publicKey[i] = chain(privateKey[i], 0, params.getWinternitzParameter() - 1, address);
		}
	}
	
	public byte[][] sign(byte[] message) {
		// create message digest
		byte messageDigest[] = new byte[params.getDigestSize()];
		Digest digest = params.getDigest();
		digest.update(message, 0, message.length);
		digest.doFinal(messageDigest, 0);
		
		List<Integer> baseWMessage = convertToBaseW(messageDigest, params.getWinternitzParameter(), params.getLen1());

		// create checksum
		int checksum = 0;
		for (int i = 0; i < params.getLen1(); i++) {
			checksum += params.getWinternitzParameter() - 1 - baseWMessage.get(i);
		}
		checksum <<= (8 - ((params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) % 8));
		int len2Bytes = (int)Math.ceil((double)(params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) / 8);
		List<Integer> baseWChecksum = convertToBaseW(XMSSUtil.toBytesBigEndian(checksum, len2Bytes), params.getWinternitzParameter(), params.getLen2());
		
		// concatenate
		baseWMessage.addAll(baseWChecksum);

		// create signature
		OTSHashAddress address = new OTSHashAddress();
		byte[][] signature = new byte[params.getLen()][];
		for (int i = 0; i < params.getLen(); i++) {
			address.setChainAddress(i);
			signature[i] = chain(privateKey[i], 0, baseWMessage.get(i), address);
		}
		return signature;
	}
	
	public boolean verifySignature(byte[] message, byte[][] signature) {
		if (signature.length != params.getLen()) {
			throw new IllegalArgumentException("wrong signature size");
		}
		
		// create message digest
		byte messageDigest[] = new byte[params.getDigestSize()];
		Digest digest = params.getDigest();
		digest.update(message, 0, message.length);
		digest.doFinal(messageDigest, 0);
		
		byte[][] tmpPublicKey = getPublicKeyFromSignature(messageDigest, signature);
		for (int i = 0; i < tmpPublicKey.length; i++) {
			for (int j = 0; j < tmpPublicKey[i].length; j++) {
				if (tmpPublicKey[i][j] != publicKey[i][j]) {
					return false;
				}
			}
		}
		return true;
	}
	
	private byte[][] getPublicKeyFromSignature(byte[] messageDigest, byte[][] signature) {
		List<Integer> baseWMessage = convertToBaseW(messageDigest, params.getWinternitzParameter(), params.getLen1());
		// create checksum
		int checksum = 0;
		for (int i = 0; i < params.getLen1(); i++) {
			checksum += params.getWinternitzParameter() - 1 - baseWMessage.get(i);
		}
		checksum <<= (8 - ((params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) % 8));
		int len2Bytes = (int)Math.ceil((double)(params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) / 8);
		List<Integer> baseWChecksum = convertToBaseW(XMSSUtil.toBytesBigEndian(checksum, len2Bytes), params.getWinternitzParameter(), params.getLen2());
		
		// concatenate
		baseWMessage.addAll(baseWChecksum);
		
		OTSHashAddress address = new OTSHashAddress();
		byte[][] res = new byte[params.getLen()][];
		for (int i = 0; i < params.getLen(); i++) {
			address.setChainAddress(i);
			res[i] = chain(signature[i], baseWMessage.get(i), params.getWinternitzParameter() - 1 - baseWMessage.get(i), address);
		}
		return res;
	}
	
	private byte[] chain(byte[] X, int startIndex, int steps, OTSHashAddress address) {
		int n = params.getDigestSize();
		if (X.length != n) {
			throw new IllegalArgumentException("X needs to be " + n + "bytes");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}	
		if ((startIndex + steps) > params.getWinternitzParameter() - 1) {
			throw new IllegalArgumentException("max chain length must not be greater than w");
		}
		
		if (steps == 0) {
			return X;
		}
		
		byte[] tmp = chain(X, startIndex, steps - 1, address);
		address.setHashAddress(startIndex + steps - 1);
		address.setKeyAndMask(0);
		byte[] key = khf.PRF(publicSeed, address);
		address.setKeyAndMask(1);
		byte[] bitmask = khf.PRF(publicSeed, address);
		byte[] tmpMasked = new byte[n];
		for (int i = 0; i < n; i++) {
			tmpMasked[i] = (byte)(tmp[i] ^ bitmask[i]);
		}
		tmp = khf.F(key, tmpMasked);
		return tmp;
	}
	
	private List<Integer> convertToBaseW(byte[] msg, int w, int outLength) {
		if (w != 4 && w != 16) {
			throw new IllegalArgumentException("w needs to be 4 or 16");
		}
		int logW = XMSSUtil.log2(w);
		if (outLength > ((8 * msg.length) / logW)) {
			throw new IllegalArgumentException("outLength too big");
		}
		
		ArrayList<Integer> res = new ArrayList<Integer>();
		for (int i = 0; i < msg.length; i++) {
			for (int j = 8 - logW; j >= 0; j -= logW) {
				res.add((msg[i] >> j) & (w-1));
				if (res.size() == outLength) {
					return res;
				}
			}
		}
		return res;
	}
	
	public WinternitzOTSPlusParameters getParams() {
		return params;
	}
	
	public byte[][] getPrivateKey() {
		return privateKey;
	}
	
	public void setPrivateKey(byte[][] privateKey) {
		this.privateKey = privateKey;
	}
	
	public byte[][] getPublicKey() {
		return publicKey;
	}
	
	public void setPublicKey(byte[][] publicKey) {
		this.publicKey = publicKey;
	}
	
	public byte[] getPublicSeed() {
		return publicSeed;
	}
	
	public void setPublicSeed(byte[] publicSeed) {
		this.publicSeed = publicSeed;
	}
}
