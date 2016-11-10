package org.bouncycastle.pqc.crypto.xmss;

import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

/**
 * XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSS {

	private XMSSParameters params;
	private WOTSPlus wotsPlus;
	private byte[] publicSeed;
	private XMSSPrivateKey privateKey;
	private XMSSPublicKey publicKey;
	private Stack<XMSSNode> stack;
	
	public XMSS(XMSSParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		publicSeed = new byte[params.getDigestSize()];
		params.getPRNG().nextBytes(publicSeed);
		WOTSPlusParameters wotsPlusParams = new WOTSPlusParameters(params.getDigest(), params.getPRNG());
		wotsPlus = new WOTSPlus(wotsPlusParams);
		stack = new Stack<XMSSNode>();
	}
	
	public void genKeyPair() {
		publicSeed = new byte[params.getDigestSize()];
		params.getPRNG().nextBytes(publicSeed);
		privateKey = new XMSSPrivateKey(this);
		XMSSNode root = treeHash(0, params.getHeight(), publicSeed, new OTSHashAddress(), new LTreeAddress(), new HashTreeAddress());
		privateKey.setRoot(root.getValue());
		publicKey = new XMSSPublicKey(this, root.getValue());
	}
	
	private XMSSNode randomizeHash(XMSSNode left, XMSSNode right, byte[] publicSeed, XMSSAddress address) {
		if (left == null) {
			throw new NullPointerException("left == null");
		}
		if (right == null) {
			throw new NullPointerException("right == null");
		}
		if (left.getHeight() != right.getHeight()) {
			throw new IllegalStateException("height of both nodes must be equal");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
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
		int n = params.getDigestSize();
		byte[] tmpMask = new byte[2 * n];
		for (int i = 0; i < n; i++) {
			tmpMask[i] = (byte)(left.getValue()[i] ^ bitmask0[i]);
		}
		for (int i = 0; i < n; i++) {
			tmpMask[i+n] = (byte)(right.getValue()[i] ^ bitmask1[i]);
		}
		byte[] out = params.getKHF().H(key, tmpMask);
		return new XMSSNode(left.getHeight(), out);
	}
	
	private XMSSNode lTree(WOTSPlusPublicKey publicKey, byte[] publicSeed, LTreeAddress address) {
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		int len = wotsPlus.getParams().getLen();
		/* duplicate public key to XMSSNode Array */
		byte[][] publicKeyBytes = publicKey.toByteArray();
		XMSSNode[] publicKeyNodes = new XMSSNode[publicKeyBytes.length];
		for (int i = 0; i < publicKeyBytes.length; i++) {
			publicKeyNodes[i] = new XMSSNode(0, publicKeyBytes[i]);
		}
		address.setTreeHeight(0);
		while (len > 1) {
			for (int i = 0; i < (int)Math.floor(len / 2); i++) {
				address.setTreeIndex(i);
				publicKeyNodes[i] = randomizeHash(publicKeyNodes[2 * i], publicKeyNodes[(2 * i) + 1], publicSeed, address);
			}
			if (len % 2 == 1) {
				publicKeyNodes[(int)Math.floor(len / 2)] = publicKeyNodes[len - 1];
			}
			len = (int)Math.ceil((double) len / 2);
			address.setTreeHeight(address.getTreeHeight() + 1);
		}
		return publicKeyNodes[0];
	}
	
	protected XMSSNode treeHash(int startIndex, int targetNodeHeight, byte[] publicSeed, OTSHashAddress otsHashAddress, LTreeAddress lTreeAddress, HashTreeAddress hashTreeAddress) {
		if (startIndex % (1 << targetNodeHeight) != 0) {
			throw new IllegalArgumentException("leaf at index startIndex needs to be a leftmost one");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		if (lTreeAddress == null) {
			throw new NullPointerException("lTreeAddress == null");
		}
		if (hashTreeAddress == null) {
			throw new NullPointerException("hashTreeAddress == null");
		}
		for (int i = 0; i < (1 << targetNodeHeight); i++) {
			otsHashAddress.setOTSAddress(startIndex + i);
			wotsPlus.generatePublicKeyFromParams(privateKey.getWOTSPlusSecretKey(startIndex + i), publicSeed, otsHashAddress);
			lTreeAddress.setLTreeAddress(startIndex + i);
			XMSSNode node = lTree(wotsPlus.getPublicKey(), publicSeed, lTreeAddress);
			hashTreeAddress.setTreeHeight(0);
			hashTreeAddress.setTreeIndex(startIndex + i);
			while(!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()) {
				hashTreeAddress.setTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2);
				node = randomizeHash(stack.pop(), node, publicSeed, hashTreeAddress);
				node.setHeight(node.getHeight() + 1);
				hashTreeAddress.setTreeHeight(hashTreeAddress.getTreeHeight() + 1);
			}
			stack.push(node);
		}
		return stack.pop();
	}
	
	/**
	 * Compute the authentication path for the i^th WOTS+ key pair.
	 * This algorithm is extremely inefficient, the use of one of the alternative algorithms is strongly RECOMMENDED.
	 * @param sk the {@link XMSSPrivateKey}
	 * @param index the {@link WOTSPlus} keypair index
	 * @param address {@link XMSSAddress} 
	 */
	private List<XMSSNode> buildAuthPath(byte[] publicSeed, OTSHashAddress address) {
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		int treeHeight = params.getHeight();
		int indexOfPublicKey = privateKey.getIndex();
		List<XMSSNode> authPath = new ArrayList<XMSSNode>();
		for (int currentHeight = 0; currentHeight < treeHeight; currentHeight++) {
			int indexOfNodeOnHeight = ((int)Math.floor(indexOfPublicKey / (1 << currentHeight))) ^ 1;
			int startLeafIndex = (indexOfNodeOnHeight * (1 << currentHeight));
			XMSSNode node = treeHash(startLeafIndex, currentHeight, publicSeed, address, new LTreeAddress(), new HashTreeAddress());
			authPath.add(node);
		}
		return authPath;
	}
	
	/**
	 * Generate a WOTS+ signature on a message with corresponding authentication path
	 * @param message n-byte message
	 * @param sk {@link XMSSPrivateKey}
	 * @param address {@link OTSHashAddress}
	 * @return Concatenation of WOTS+ signature and authentication path
	 */
	private XMSSSignature treeSig(byte[] messageDigest, byte[] publicSeed, OTSHashAddress address) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		/* recreate WOTSPlus state at index */
		int index = privateKey.getIndex();
		resetWOTSPlusState(index, publicSeed);
		
		/* create WOTS+ signature */
		address.setOTSAddress(privateKey.getIndex());
		WOTSPlusSignature wotsSignature = wotsPlus.sign(messageDigest, publicSeed, address);
		
		/* add authPath */
		List<XMSSNode> authPath = buildAuthPath(publicSeed, address);
		
		/* assemble temp signature */
		XMSSSignature tmpSignature = new XMSSSignature(wotsSignature, authPath);
		return tmpSignature;
	}

	public XMSSSignature sign(byte[] message) {
		if (publicKey == null || privateKey == null) {
			throw new IllegalStateException("no key has been generated");
		}
		KeyedHashFunctions khf = params.getKHF();
		/* create (randomized keyed) messageDigest of message */
		int index = privateKey.getIndex();
		byte[] random = khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(index, 32));
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		/* create signature for messageDigest */
		XMSSSignature signature = treeSig(messageDigest, publicSeed, new OTSHashAddress());
		signature.setIndex(index);
		signature.setRandom(random);
		
		/* update index */
		privateKey.setIndex(index + 1);
		
		return signature;
	}
	
	/**
	 * Compute a root node from a tree signature
	 * @param sig the {@link XMSSSignature}
	 * @param message n-byte long message
	 * @return the root as {@link XMSSNode}
	 */
	protected XMSSNode getRootNodeFromSignature(byte[] messageDigest, XMSSSignature signature, byte[] publicSeed) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
		}
		/* calculate WOTS+ public key and compress to obtain original leaf hash */
		int index = signature.getIndex();
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setOTSAddress(index);
		WOTSPlusPublicKey wotsPlusPK = wotsPlus.getPublicKeyFromSignature(messageDigest, signature.getSignature(), publicSeed, otsHashAddress);
		LTreeAddress ltreeAddress = new LTreeAddress();
		ltreeAddress.setLTreeAddress(index);
		XMSSNode[] node = new XMSSNode[2];
		node[0] = lTree(wotsPlusPK, publicSeed, ltreeAddress);
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		hashTreeAddress.setTreeIndex(index);
		for (int k = 0; k < params.getHeight(); k++){
			hashTreeAddress.setTreeHeight(k);
			if (Math.floor(index / (1 << k)) % 2 == 0) {
				hashTreeAddress.setTreeIndex(hashTreeAddress.getTreeIndex() / 2);
				node[1] = randomizeHash(node[0], signature.getAuthPath().get(k), publicSeed, hashTreeAddress);
				node[1].setHeight(node[1].getHeight() + 1);
			} else {
				hashTreeAddress.setTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2);
				node[1] = randomizeHash(signature.getAuthPath().get(k), node[0], publicSeed, hashTreeAddress);
				node[1].setHeight(node[1].getHeight() + 1);
			}
			node[0] = node[1];
		}
		return node[0];
	}
	
	/**
	 * Verify an XMSS signature using the corresponding XMSS public key and a message
	 * @param sig {@link XMSSSignature}
	 * @param message
	 * @return returns true if and only if Sig is a valid signature on M under public key PK.  Otherwise, it returns false.
	 */
	public boolean verifySignature(byte[] message, XMSSSignature signature, XMSSPublicKey publicKey) {
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		byte[] concatenated = XMSSUtil.concat(signature.getRandom(), publicKey.getRoot(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		byte[] messageDigest = params.getKHF().HMsg(concatenated, message);
		XMSSNode rootNodeFromSignature = getRootNodeFromSignature(messageDigest, signature, publicKey.getPublicSeed());
		return XMSSUtil.compareByteArray(rootNodeFromSignature.getValue(), publicKey.getRoot());
	}
	
	private void resetWOTSPlusState(int index, byte[] publicSeed) {
		if (publicSeed.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
		}
		OTSHashAddress address = new OTSHashAddress();
		address.setOTSAddress(index);
		wotsPlus.generatePublicKeyFromParams(privateKey.getWOTSPlusSecretKey(index), publicSeed, address);
	}
	
	public XMSSParameters getParams() {
		return params;
	}
	
	public byte[] getPublicSeed() {
		return publicSeed;
	}
	
	public XMSSPublicKey getPublicKey() {
		if (publicKey == null) {
			throw new IllegalStateException("no key has been generated");
		}
		return publicKey;
	}
	
	public XMSSPrivateKey getPrivateKey() {
		if (privateKey == null) {
			throw new IllegalStateException("no key has been generated");
		}
		return privateKey;
    }
}
