package org.bouncycastle.pqc.crypto.xmss;

import java.util.ArrayList;
import java.util.List;

/**
 * This class implements the WOTS+ one-time signature system
 * as described in draft-irtf-cfrg-xmss-hash-based-signatures-06.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class WOTSPlus {

	/**
	 * WOTS+ parameters.
	 */
	private WOTSPlusParameters params;
	/**
	 * WOTS+ secret key seed.
	 */
	private byte[] secretKeySeed;
	/**
	 * WOTS+ public seed.
	 */
	private byte[] publicSeed;
	/**
	 * Keyed hash function.
	 */
	private KeyedHashFunctions khf;

	/**
	 * Constructs a new WOTS+ one-time signature system based on the given WOTS+ parameters.
	 */
	public WOTSPlus(WOTSPlusParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		khf = new KeyedHashFunctions(params.getDigest());
	}
	/**
	 * (Re)Initializes the internal state.
	 */
	public void initialize(byte[] secretKeySeed, byte[] publicSeed) {
		if (secretKeySeed == null) {
			throw new NullPointerException("secretKeySeed == null");
		}
		if (secretKeySeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of secretKeySeed needs to be equal to size of digest");
		}
		if (publicSeed == null) {
			throw new NullPointerException("publicSeed == null");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
		}
		this.secretKeySeed = secretKeySeed;
		this.publicSeed = publicSeed;
	}
	
	public WOTSPlusPublicKey getPublicKey(OTSHashAddress otsHashAddress) {
		checkState();
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		byte[][] publicKey = new byte[params.getLen()][];
		for (int i = 0; i < params.getLen(); i++) {
			otsHashAddress.setChainAddress(i);
			publicKey[i] = chain(expandSecretKeySeed(i), 0, params.getWinternitzParameter() - 1, otsHashAddress);
		}
		return new WOTSPlusPublicKey(publicKey);
	}
	
	public WOTSPlusSignature sign(byte[] messageDigest, OTSHashAddress otsHashAddress) {
		checkState();
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		List<Integer> baseWMessage = convertToBaseW(messageDigest, params.getWinternitzParameter(), params.getLen1());
		/* create checksum */
		int checksum = 0;
		for (int i = 0; i < params.getLen1(); i++) {
			checksum += params.getWinternitzParameter() - 1 - baseWMessage.get(i);
		}
		checksum <<= (8 - ((params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) % 8));
		int len2Bytes = (int)Math.ceil((double)(params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) / 8);
		List<Integer> baseWChecksum = convertToBaseW(XMSSUtil.toBytesBigEndian(checksum, len2Bytes), params.getWinternitzParameter(), params.getLen2());
		
		/* msg || checksum */
		baseWMessage.addAll(baseWChecksum);

		/* create signature */
		byte[][] signature = new byte[params.getLen()][];
		for (int i = 0; i < params.getLen(); i++) {
			otsHashAddress.setChainAddress(i);
			signature[i] = chain(expandSecretKeySeed(i), 0, baseWMessage.get(i), otsHashAddress);
		}
		return new WOTSPlusSignature(signature);
	}
	
	public boolean verifySignature(byte[] messageDigest, WOTSPlusSignature signature, OTSHashAddress otsHashAddress) {
		checkState();
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (XMSSUtil.hasNullPointer(signature.toByteArray())) {
			throw new NullPointerException("signature byte array == null");
		}
		if (signature.toByteArray().length != params.getLen()) {
			throw new IllegalArgumentException("wrong signature size");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		if (otsHashAddress.toByteArray() == null) {
			throw new NullPointerException("otsHashAddress byte array == null");
		}
		byte[][] tmpPublicKey = getPublicKeyFromSignature(messageDigest, signature, otsHashAddress).toByteArray();
		/* compare values */
		return XMSSUtil.compareByteArray(tmpPublicKey, getPublicKey(otsHashAddress).toByteArray()) ? true : false;
	}
	
	public WOTSPlusPublicKey getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature, OTSHashAddress otsHashAddress) {
		checkState();
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (XMSSUtil.hasNullPointer(signature.toByteArray())) {
			throw new NullPointerException("signature byte array == null");
		}
		if (signature.toByteArray().length != params.getLen()) {
			throw new IllegalArgumentException("wrong signature size");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		if (otsHashAddress.toByteArray() == null) {
			throw new NullPointerException("otsHashAddress byte array == null");
		}
		List<Integer> baseWMessage = convertToBaseW(messageDigest, params.getWinternitzParameter(), params.getLen1());
		/* create checksum */
		int checksum = 0;
		for (int i = 0; i < params.getLen1(); i++) {
			checksum += params.getWinternitzParameter() - 1 - baseWMessage.get(i);
		}
		checksum <<= (8 - ((params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) % 8));
		int len2Bytes = (int)Math.ceil((double)(params.getLen2() * XMSSUtil.log2(params.getWinternitzParameter())) / 8);
		List<Integer> baseWChecksum = convertToBaseW(XMSSUtil.toBytesBigEndian(checksum, len2Bytes), params.getWinternitzParameter(), params.getLen2());
		
		/* msg || checksum */
		baseWMessage.addAll(baseWChecksum);
		
		byte[][] publicKey = new byte[params.getLen()][];
		for (int i = 0; i < params.getLen(); i++) {
			otsHashAddress.setChainAddress(i);
			publicKey[i] = chain(signature.toByteArray()[i], baseWMessage.get(i), params.getWinternitzParameter() - 1 - baseWMessage.get(i), otsHashAddress);
		}
		return new WOTSPlusPublicKey(publicKey);
	}
	
	private byte[] chain(byte[] startHash, int startIndex, int steps, OTSHashAddress otsHashAddress) {
		checkState();
		int n = params.getDigestSize();
		if (startHash.length != n) {
			throw new IllegalArgumentException("startHash needs to be " + n + "bytes");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		if (otsHashAddress.toByteArray() == null) {
			throw new NullPointerException("otsHashAddress byte array == null");
		}
		if ((startIndex + steps) > params.getWinternitzParameter() - 1) {
			throw new IllegalArgumentException("max chain length must not be greater than w");
		}
		
		if (steps == 0) {
			return startHash;
		}
		
		byte[] tmp = chain(startHash, startIndex, steps - 1, otsHashAddress);
		otsHashAddress.setHashAddress(startIndex + steps - 1);
		otsHashAddress.setKeyAndMask(0);
		byte[] key = khf.PRF(publicSeed, otsHashAddress.toByteArray());
		otsHashAddress.setKeyAndMask(1);
		byte[] bitmask = khf.PRF(publicSeed, otsHashAddress.toByteArray());
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
	
	private void checkState() {
		if (secretKeySeed == null || publicSeed == null) {
			throw new IllegalStateException("not initialized");
		}
	}
	
	private byte[] expandSecretKeySeed(int index) {
		checkState();
		if (index < 0 || index >= params.getLen()) {
			throw new IllegalArgumentException("index out of bounds");
		}
		return khf.PRF(secretKeySeed, XMSSUtil.toBytesBigEndian(index, 32));
	}

	public WOTSPlusParameters getParams() {
		return params;
	}
	
	public byte[] getPublicSeed() {
		checkState();
		return publicSeed;
	}
	
	public KeyedHashFunctions getKhf() {
		return khf;
	}
	
	public byte[] getSecretKeySeed() {
		checkState();
		return secretKeySeed;
	}
	
	public WOTSPlusPrivateKey getPrivateKey() {
		checkState();
		byte[][] privateKey = new byte[params.getLen()][];
		for (int i = 0; i < privateKey.length; i++) {
			privateKey[i] = expandSecretKeySeed(i);
		}
		return new WOTSPlusPrivateKey(privateKey);
	}
}
