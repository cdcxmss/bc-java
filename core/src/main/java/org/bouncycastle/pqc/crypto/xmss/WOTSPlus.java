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
	 * Randomization functions.
	 */
	private KeyedHashFunctions khf;
	/**
	 * WOTS+ secret key seed.
	 */
	private byte[] secretKeySeed;
	/**
	 * WOTS+ public seed.
	 */
	private byte[] publicSeed;

	/**
	 * Constructs a new WOTS+ one-time signature system based on the given WOTS+ parameters.
	 * @param params Parameters for WOTSPlus object.
	 */
	protected WOTSPlus(WOTSPlusParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		khf = new KeyedHashFunctions(params.getDigest(), params.getDigestSize());
	}

	/**
	 * Import keys to WOTS+ instance.
	 * @param secretKeySeed Secret key seed.
	 * @param publicSeed Public seed.
	 */
	protected void importKeys(byte[] secretKeySeed, byte[] publicSeed) {
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
	
	/**
	 * Calculates a new public key based on the state of secretKeySeed, publicSeed and otsHashAddress.
	 * @param otsHashAddress OTS hash address for randomization.
	 * @return WOTS+ public key.
	 */
	protected WOTSPlusPublicKey getPublicKey(OTSHashAddress otsHashAddress) {
		checkState();
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		byte[][] publicKey = new byte[params.getLen()][];
		/* derive public key from secretKeySeed */
		for (int i = 0; i < params.getLen(); i++) {
			otsHashAddress.setChainAddress(i);
			publicKey[i] = chain(expandSecretKeySeed(i), 0, params.getWinternitzParameter() - 1, otsHashAddress);
		}
		return new WOTSPlusPublicKey(params, publicKey);
	}
	
	/**
	 * Calculates a new public key based on the state of secretKeySeed, publicSeed and otsHashAddress.
	 * @param otsHashAddress OTS hash address for randomization.
	 * @return WOTS+ public key.
	 */
	protected WOTSPlusPublicKey getPublicKey(OTSHashAddress otsHashAddress, byte[] skSeed, byte[] pubSeed) {
//		checkState();
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		byte[][] publicKey = new byte[params.getLen()][];
		/* derive public key from secretKeySeed */
		for (int i = 0; i < params.getLen(); i++) {
			otsHashAddress.setChainAddress(i);
			byte[] expandedSeed = expandSecretKeySeed(i, skSeed);
			publicKey[i] = chain(expandedSeed, 0, params.getWinternitzParameter() - 1, pubSeed, otsHashAddress);
		}
		return new WOTSPlusPublicKey(params, publicKey);
	}
	
	/**
	 * Creates a signature for the n-byte messageDigest.
	 * @param messageDigest Digest to sign.
	 * @param otsHashAddress OTS hash address for randomization.
	 * @return WOTS+ signature.
	 */
	protected WOTSPlusSignature sign(byte[] messageDigest, OTSHashAddress otsHashAddress) {
		checkState();
		if (messageDigest == null) {
			throw new NullPointerException("messageDigest == null");
		}
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
		return new WOTSPlusSignature(params, signature);
	}
	
	/**
	 * Creates a signature for the n-byte messageDigest.
	 * @param messageDigest Digest to sign.
	 * @param otsHashAddress OTS hash address for randomization.
	 * @return WOTS+ signature.
	 */
	protected WOTSPlusSignature sign(byte[] messageDigest, byte[] pkSeed, OTSHashAddress otsHashAddress) {
		checkState();
		if (messageDigest == null) {
			throw new NullPointerException("messageDigest == null");
		}
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
			signature[i] = chain(expandSecretKeySeed(i), 0, baseWMessage.get(i), pkSeed, otsHashAddress);
		}
		return new WOTSPlusSignature(params, signature);
	}
	
	/**
	 * Verifies signature on message.
	 * @param messageDigest The digest that was signed.
	 * @param signature Signature on digest.
	 * @param otsHashAddress OTS hash address for randomization.
	 * @return true if signature was correct false else.
	 */
	protected boolean verifySignature(byte[] messageDigest, WOTSPlusSignature signature, OTSHashAddress otsHashAddress) {
		checkState();
		if (messageDigest == null) {
			throw new NullPointerException("messageDigest == null");
		}
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		byte[][] tmpPublicKey = getPublicKeyFromSignature(messageDigest, signature, otsHashAddress).toByteArray();
		/* compare values */
		return XMSSUtil.compareByteArray(tmpPublicKey, getPublicKey(otsHashAddress).toByteArray()) ? true : false;
	}

	/**
	 * Calculates a public key based on digest and signature.
	 * @param messageDigest The digest that was signed.
	 * @param signature Signarure on digest.
	 * @param otsHashAddress OTS hash address for randomization.
	 * @return WOTS+ public key derived from digest and signature.
	 */
	protected WOTSPlusPublicKey getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature, OTSHashAddress otsHashAddress) {
		checkState();
		if (messageDigest == null) {
			throw new NullPointerException("messageDigest == null");
		}
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
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
		
		byte[][] publicKey = new byte[params.getLen()][];
		for (int i = 0; i < params.getLen(); i++) {
			otsHashAddress.setChainAddress(i);
			publicKey[i] = chain(signature.toByteArray()[i], baseWMessage.get(i), params.getWinternitzParameter() - 1 - baseWMessage.get(i), otsHashAddress);
		}
		return new WOTSPlusPublicKey(params, publicKey);
	}
	
	/**
	 * Calculates a public key based on digest and signature.
	 * @param messageDigest The digest that was signed.
	 * @param signature Signarure on digest.
	 * @param otsHashAddress OTS hash address for randomization.
	 * @param publicSeed
	 * @return WOTS+ public key derived from digest and signature.
	 */
	protected WOTSPlusPublicKey getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature, OTSHashAddress otsHashAddress, byte[] publicSeed) {
//		checkState();
		if (messageDigest == null) {
			throw new NullPointerException("messageDigest == null");
		}
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
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
		
		byte[][] publicKey = new byte[params.getLen()][];
		for (int i = 0; i < params.getLen(); i++) {
			otsHashAddress.setChainAddress(i);
			publicKey[i] = chain(signature.toByteArray()[i], baseWMessage.get(i), params.getWinternitzParameter() - 1 - baseWMessage.get(i), publicSeed, otsHashAddress);
		}
		return new WOTSPlusPublicKey(params, publicKey);
	}
	
	/**
	 * Computes an iteration of F on an n-byte input using outputs of PRF.
	 * @param startHash Starting point.
	 * @param startIndex Start index.
	 * @param steps Steps to take.
	 * @param otsHashAddress OTS hash address for randomization.
	 * @return Value obtained by iterating F for steps times on input startHash, using the outputs of PRF.
	 */
	private byte[] chain(byte[] startHash, int startIndex, int steps, OTSHashAddress otsHashAddress) {
		checkState();
		int n = params.getDigestSize();
		if (startHash == null) {
			throw new NullPointerException("startHash == null");
		}
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
	
	/**
	 * Computes an iteration of F on an n-byte input using outputs of PRF.
	 * @param startHash Starting point.
	 * @param startIndex Start index.
	 * @param steps Steps to take.
	 * @param publicSeed
	 * @param otsHashAddress OTS hash address for randomization.
	 * @return Value obtained by iterating F for steps times on input startHash, using the outputs of PRF.
	 */
	private byte[] chain(byte[] startHash, int startIndex, int steps, byte[] publicSeed, OTSHashAddress otsHashAddress) {
		//checkState();
		int n = params.getDigestSize();
		int w = params.getWinternitzParameter();
		if (startHash == null) {
			throw new NullPointerException("startHash == null");
		}
		if (startHash.length != n) {
			throw new IllegalArgumentException("startHash needs to be " + n + "bytes");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		if (otsHashAddress.toByteArray() == null) {
			throw new NullPointerException("otsHashAddress byte array == null");
		}
		if ((startIndex + steps) > w - 1) {
			throw new IllegalArgumentException("max chain length must not be greater than w");
		}
		
		if (steps == 0) {
			return startHash;
		}
		
		byte[] tmp = startHash;
		for (int i = startIndex; i < (startIndex + steps) && i < w; i++) {//er kommt heir oben immer mit hash = 0 und mit key = i an
			otsHashAddress.setHashAddress(i);//sieht aus als würde er anstatt hashaddr den key auf i setzen und nichts mit hash machen - beim i=6 ist hash am ende =1 und beim i=7 ist i=0 am anfang ist key = 0
			otsHashAddress.setKeyAndMask(0);
			byte[] key = khf.PRF(publicSeed, otsHashAddress.toByteArray());
			otsHashAddress.setKeyAndMask(1);
			byte[] bitmask = khf.PRF(publicSeed, otsHashAddress.toByteArray());
			byte[] tmpMasked = new byte[n];
			for (int j = 0; j < n; j++) {
				tmpMasked[j] = (byte)(tmp[j] ^ bitmask[j]);
			}
			tmp = khf.F(key, tmpMasked);
		}
		return tmp;
	}
	
	/**
	 * Obtain base w values from Input.
	 * @param messageDigest Input data.
	 * @param w Base.
	 * @param outLength Length of output.
	 * @return outLength-length list of base w integers. 
	 */
	private List<Integer> convertToBaseW(byte[] messageDigest, int w, int outLength) {
		if (messageDigest == null) {
			throw new NullPointerException("msg == null");
		}
		if (w != 4 && w != 16) {
			throw new IllegalArgumentException("w needs to be 4 or 16");
		}
		int logW = XMSSUtil.log2(w);
		if (outLength > ((8 * messageDigest.length) / logW)) {
			throw new IllegalArgumentException("outLength too big");
		}
		
		ArrayList<Integer> res = new ArrayList<Integer>();
		for (int i = 0; i < messageDigest.length; i++) {
			for (int j = 8 - logW; j >= 0; j -= logW) {
				res.add((messageDigest[i] >> j) & (w-1));
				if (res.size() == outLength) {
					return res;
				}
			}
		}
		return res;
	}
	
	/**
	 * Check whether keys are set.
	 */
	private void checkState() {
		if (secretKeySeed == null || publicSeed == null) {//
			throw new IllegalStateException("not initialized");
		}
	}
	
	/**
	 * Derive private key at index from secret key seed.
	 * @param index Index.
	 * @return Private key at index.
	 */
	private byte[] expandSecretKeySeed(int index) {
		checkState();
		if (index < 0 || index >= params.getLen()) {
			throw new IllegalArgumentException("index out of bounds");
		}
		return khf.PRF(secretKeySeed, XMSSUtil.toBytesBigEndian(index, 32));
	}
	
	/**
	 * Expands an n-byte array into a len*n byte array.
	 * @param byte[] skSeed.
	 * @return byte[] Expanded private key seed.
	 */
	private byte[] expandSecretKeySeed(int index, byte[] skSeed) {
		//checkState();
		byte[] expandedSeed = null;
		byte[] bytes = XMSSUtil.toBytesBigEndian(index, 32);
		expandedSeed = khf.PRF(skSeed, bytes);
		return expandedSeed;
	}

	/**
	 * Getter parameters.
	 * @return params.
	 */
	public WOTSPlusParameters getParams() {
		return params;
	}
	
	/**
	 * Getter public seed.
	 * @return public seed.
	 */
	protected byte[] getPublicSeed() {
		checkState();
		return publicSeed;
	}
	
	/**
	 * Getter keyed hash functions.
	 * @return keyed hash functions.
	 */
	protected KeyedHashFunctions getKhf() {
		return khf;
	}
	
	/**
	 * Getter secret key seed.
	 * @return secret key seed.
	 */
	protected byte[] getSecretKeySeed() {
		checkState();
		return secretKeySeed;
	}
	
	/**
	 * Getter private key.
	 * @return WOTS+ private key.
	 */
	protected WOTSPlusPrivateKey getPrivateKey() {
		checkState();
		byte[][] privateKey = new byte[params.getLen()][];
		for (int i = 0; i < privateKey.length; i++) {
			privateKey[i] = expandSecretKeySeed(i);
		}
		return new WOTSPlusPrivateKey(params, privateKey);
	}
}
