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
	 * Public Seed.
	 */
	private byte[] publicSeed;
	/**
	 * Keyed hash function.
	 */
	private KeyedHashFunctions khf;
	/**
	 * WOTS+ secret key seed.
	 */
	private byte[] secretKeySeed;
	/**
	 * WOTS+ public key.
	 */
	private WOTSPlusPublicKey publicKey;

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
	
	public void generateKeys() {
		publicSeed = new byte[params.getDigestSize()];
		params.getPRNG().nextBytes(publicSeed);
		secretKeySeed = generateSecretKeySeed();
		publicKey = generatePublicKey(publicSeed, new OTSHashAddress());
	}
	
	private byte[] generateSecretKeySeed() {
		byte[] secretKeySeed = new byte[params.getDigestSize()];
		params.getPRNG().nextBytes(secretKeySeed);
		return secretKeySeed;
	}
	
	protected void generatePublicKeyFromParams(byte[] secretKeySeed, byte[] publicSeed, OTSHashAddress address) {
		if (secretKeySeed == null) {
			throw new IllegalStateException("secretKeySeed == null");
		}
		if (secretKeySeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("length of secretKeySeed must be size of digest");
		}
		if (publicSeed == null) {
			throw new IllegalStateException("publicSeed == null");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("length of publicSeed must be size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		this.secretKeySeed = secretKeySeed;
		this.publicSeed = publicSeed;
		publicKey = generatePublicKey(publicSeed, address);
	}
	
	private WOTSPlusPublicKey generatePublicKey(byte[] publicSeed, OTSHashAddress address) {
		if (publicSeed == null) {
			throw new IllegalStateException("publicSeed == null");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("length of publicSeed must be size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		byte[][] publicKey = new byte[params.getLen()][];
		for (int i = 0; i < params.getLen(); i++) {
			address.setChainAddress(i);
			publicKey[i] = chain(expandSecretKeySeed(i), 0, params.getWinternitzParameter() - 1, publicSeed, address);
		}
		return new WOTSPlusPublicKey(publicKey);
	}
	
	public WOTSPlusSignature sign(byte[] messageDigest) {
		return sign(messageDigest, publicSeed, new OTSHashAddress());
	}
	
	protected WOTSPlusSignature sign(byte[] messageDigest, byte[] publicSeed, OTSHashAddress address) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (publicSeed == null) {
			throw new IllegalStateException("publicSeed == null");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("length of publicSeed must be size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		if (secretKeySeed == null || publicKey == null) {
			throw new IllegalStateException("no key has been generated");
		}
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
		byte[][] signature = new byte[params.getLen()][];
		for (int i = 0; i < params.getLen(); i++) {
			address.setChainAddress(i);
			signature[i] = chain(expandSecretKeySeed(i), 0, baseWMessage.get(i), publicSeed, address);
		}
		return new WOTSPlusSignature(signature);
	}
	
	public boolean verifySignature(byte[] messageDigest, WOTSPlusSignature signature) {
		return verifySignature(messageDigest, signature, publicSeed, new OTSHashAddress());
	}
	
	protected boolean verifySignature(byte[] messageDigest, WOTSPlusSignature signature, byte[] publicSeed, OTSHashAddress address) {
		if (publicKey == null) {
			throw new IllegalStateException("no key has been generated");
		}
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (signature.toByteArray().length != params.getLen()) {
			throw new IllegalArgumentException("wrong signature size");
		}
		if (publicSeed == null) {
			throw new IllegalStateException("publicSeed == null");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("length of publicSeed must be size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		byte[][] tmpPublicKey = getPublicKeyFromSignature(messageDigest, signature, publicSeed, address).toByteArray();
		/* compare values */
		for (int i = 0; i < tmpPublicKey.length; i++) {
			for (int j = 0; j < tmpPublicKey[i].length; j++) {
				if (tmpPublicKey[i][j] != publicKey.toByteArray()[i][j]) {
					return false;
				}
			}
		}
		return true;
	}
	
	protected WOTSPlusPublicKey getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature, byte[] publicSeed, OTSHashAddress address) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
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
		
		byte[][] publicKey = new byte[params.getLen()][];
		for (int i = 0; i < params.getLen(); i++) {
			address.setChainAddress(i);
			publicKey[i] = chain(signature.toByteArray()[i], baseWMessage.get(i), params.getWinternitzParameter() - 1 - baseWMessage.get(i), publicSeed, address);
		}
		return new WOTSPlusPublicKey(publicKey);
	}
	
	private byte[] chain(byte[] X, int startIndex, int steps, byte[] publicSeed, OTSHashAddress address) {
		int n = params.getDigestSize();
		if (X.length != n) {
			throw new IllegalArgumentException("X needs to be " + n + "bytes");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
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
		
		byte[] tmp = chain(X, startIndex, steps - 1, publicSeed, address);
		address.setHashAddress(startIndex + steps - 1);
		address.setKeyAndMask(0);
		byte[] key = khf.PRF(publicSeed, address.toByteArray());
		address.setKeyAndMask(1);
		byte[] bitmask = khf.PRF(publicSeed, address.toByteArray());
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
	
	private byte[] expandSecretKeySeed(int index) {
		if (secretKeySeed == null) {
			throw new IllegalStateException("secretKeySeed == null");
		}
		if (index < 0 || index >= params.getLen()) {
			throw new IllegalArgumentException("index out of bounds");
		}
		return khf.PRF(secretKeySeed, XMSSUtil.toBytesBigEndian(index, 32));
	}

	public WOTSPlusParameters getParams() {
		return params;
	}
	
	public byte[] getPublicSeed() {
		if (publicSeed == null) {
			throw new IllegalStateException("publicSeed == null");
		}
		return publicSeed;
	}
	
	public KeyedHashFunctions getKhf() {
		return khf;
	}
	
	public byte[] getSecretKeySeed() {
		if (secretKeySeed == null) {
			throw new IllegalStateException("secretKeySeed == null");
		}
		return secretKeySeed;
	}
	
	protected void setSecretKeySeed(byte[] secretKeySeed) {
		if (secretKeySeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("length of secretKeySeed must be size of digest");
		}
		this.secretKeySeed = secretKeySeed;
	}
	
	public WOTSPlusPrivateKey getPrivateKey() {
		if (secretKeySeed == null) {
			throw new IllegalStateException("privateKey == null");
		}
		byte[][] privateKey = new byte[params.getLen()][];
		for (int i = 0; i < privateKey.length; i++) {
			privateKey[i] = expandSecretKeySeed(i);
		}
		return new WOTSPlusPrivateKey(privateKey);
	}
	
	public WOTSPlusPublicKey getPublicKey() {
		if (publicKey == null) {
			throw new IllegalStateException("no key has been generated");
		}
		return publicKey;
	}
}
