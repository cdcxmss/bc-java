package org.bouncycastle.pqc.crypto.xmss;

/**
 * XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSS {

	private XMSSParameters params;
	private byte[] publicSeed;
	private XMSSPrivateKey privateKey;
	private XMSSPublicKey publicKey;
	private WinternitzOTSPlus wotsPlus;
	
	public XMSS(XMSSParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		publicSeed = new byte[params.getDigestSize()];
		params.getPRNG().nextBytes(publicSeed);
		WinternitzOTSPlusParameters wotsPlusParams = new WinternitzOTSPlusParameters(params.getDigest(), params.getPRNG(), params.getWinternitzParameter());
		wotsPlus = new WinternitzOTSPlus(wotsPlusParams, publicSeed);
	}
	
	public void genKeyPair() {
		
	}
	
	private byte[] randomizeHash(byte[] left, byte[] right, XMSSAddress address) {
		int n = params.getDigestSize();
		if (left.length != n) {
			throw new IllegalArgumentException("size of left needs to be equal to size of digest");
		}
		if (right.length != n) {
			throw new IllegalArgumentException("size of right needs to be equal to size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		address.setKeyAndMask(0);
		byte[] key = params.getKHF().PRF(publicSeed, address.toByteArray());
		address.setKeyAndMask(1);
		byte[] bitmask0 = params.getKHF().PRF(publicSeed, address.toByteArray());
		address.setKeyAndMask(2);
		byte[] bitmask1 = params.getKHF().PRF(publicSeed, address.toByteArray());
		byte[] tmpMask = new byte[2 * n];
		for (int i = 0; i < n; i++) {
			tmpMask[i] = (byte)(left[i] ^ bitmask0[i]);
		}
		for (int i = 0; i < n; i++) {
			tmpMask[i+n] = (byte)(right[i] ^ bitmask1[i]);
		}
		return params.getKHF().H(key, tmpMask);
	}
	
	private XMSSNode treeHash(XMSSPrivateKey sk, int i, int j, XMSSAddress address) {
		return null;
	}

	private byte[] lTree(LTreeAddress address) {
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		byte[][] publicKey = XMSSUtil.cloneArray(wotsPlus.getPublicKey());
		int len = wotsPlus.getParams().getLen();
		address.setTreeHeight(0);
		while (len > 1) {
			for (int i = 0; i < (int)Math.floor((double) len / 2); i++) {
				address.setTreeIndex(i);
				publicKey[i] = randomizeHash(publicKey[2 * i], publicKey[(2 * i) + 1], address);
			}
			if (len % 2 == 1) {
				publicKey[(int)Math.floor((double)len / 2)] = publicKey[len - 1];
			}
			len = (int)Math.ceil((double) len / 2);
			address.setTreeHeight(address.getTreeHeight() + 1);
		}
		return publicKey[0];
	}
	
	public XMSSParameters getParams() {
		return params;
	}
	
	public byte[] getPublicSeed() {
		return publicSeed;
	}
	
	/**
	 * Compute the authentication path for the i^th WOTS+ key pair.
	 * This algorithm is extremely inefficient, the use of one of the alternative algorithms is strongly RECOMMENDED.
	 * @param sk the {@link XMSSPrivateKey}
	 * @param index the {@link WinternitzOTSPlus} key par index
	 * @param address {@link XMSSAddress} 
	 */
	private XMSSNode[] buildAuth(XMSSPrivateKey sk, int index, XMSSAddress address){
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		if (sk == null) {
			throw new NullPointerException("sk == null");
		}
		int h = params.getHeight();
		XMSSNode[] auth = new XMSSNode[h-1];
		for (int j = 0; j < h; j++){
			int k = (int)Math.floor(index / (Math.pow(2, j))) ^ 1;
			auth[j] = treeHash(sk, (int)(k * Math.pow(2, j)), j, address);
		}
		return auth;
	}
	
	/**
	 * Generate a WOTS+ signature on a message with corresponding authentication path
	 * @param message n-byte message
	 * @param sk {@link XMSSPrivateKey}
	 * @param address {@link OTSHashAddress}
	 * @return Concatenation of WOTS+ signature and authentication path
	 */
	private byte[] treeSig(byte[] message, XMSSPrivateKey sk, OTSHashAddress address){
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		if (sk == null) {
			throw new NullPointerException("sk == null");
		}
		int index = sk.getIndex();
		XMSSNode[] auth = buildAuth(sk, index, address);
		address.setOTSAddress(index);
		byte[][] otsSignature = wotsPlus.sign(message);//parameters index, address, wots sk?
		WinternitzOTSPlusParameters wotsPlusParams = wotsPlus.getParams();
		byte[] tmpSig = new byte[wotsPlusParams.getLen() * wotsPlusParams.getDigestSize() + params.getHeight()-1 * params.getDigestSize()];
		for (int i = 0; i < otsSignature.length; i++){
			for (int j = 0; j < otsSignature[i].length; j++){
				tmpSig[i*otsSignature.length+j] = otsSignature[i][j];
			}
		}
		for (int i = 0; i < auth.length; i++){
			for (int j = 0; j < auth[i].getValue().length; j++){
				tmpSig[wotsPlusParams.getLen() * wotsPlusParams.getDigestSize()+i*auth.length+j] = auth[i].getValue()[j];
			}
		}
		return tmpSig;
		
	}
	
	public void sign(){
		
	}
}
