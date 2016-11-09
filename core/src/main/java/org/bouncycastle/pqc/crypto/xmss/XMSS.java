package org.bouncycastle.pqc.crypto.xmss;

import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

/**
 * XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
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
		wotsPlus = new WOTSPlus(wotsPlusParams, publicSeed);
		stack = new Stack<XMSSNode>();
	}
	
	public void genKeyPair() {
		privateKey = new XMSSPrivateKey(this);
		XMSSNode root = treeHash(0, params.getHeight(), new OTSHashAddress(), new LTreeAddress(), new HashTreeAddress());
		privateKey.setRoot(root.getValue());
		publicKey = new XMSSPublicKey(this, root.getValue());
	}
	
	private XMSSNode randomizeHash(XMSSNode left, XMSSNode right, XMSSAddress address) {
		if (left == null) {
			throw new NullPointerException("left == null");
		}
		if (right == null) {
			throw new NullPointerException("right == null");
		}
		if (left.getHeight() != right.getHeight()) {
			throw new IllegalStateException("height of both nodes must be equal");
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
	
	private XMSSNode lTree(LTreeAddress address) {
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		int len = wotsPlus.getParams().getLen();
		/* duplicate public key to XMSSNode Array */
		byte[][] publicKey = wotsPlus.getPublicKey().toByteArray();
		XMSSNode[] publicKeyNodes = new XMSSNode[publicKey.length];
		for (int i = 0; i < publicKey.length; i++) {
			publicKeyNodes[i] = new XMSSNode(0, publicKey[i]);
		}
		address.setTreeHeight(0);
		while (len > 1) {
			for (int i = 0; i < (int)Math.floor((double) len / 2); i++) {
				address.setTreeIndex(i);
				publicKeyNodes[i] = randomizeHash(publicKeyNodes[2 * i], publicKeyNodes[(2 * i) + 1], address);
			}
			if (len % 2 == 1) {
				publicKeyNodes[(int)Math.floor((double)len / 2)] = publicKeyNodes[len - 1];
			}
			len = (int)Math.ceil((double) len / 2);
			address.setTreeHeight(address.getTreeHeight() + 1);
		}
		return publicKeyNodes[0];
	}
	
	protected XMSSNode treeHash(int startIndex, int targetNodeHeight, OTSHashAddress otsHashAddress, LTreeAddress lTreeAddress, HashTreeAddress hashTreeAddress) {
		if (startIndex % (1 << targetNodeHeight) != 0) {
			throw new IllegalArgumentException("leaf at index startIndex needs to be a leftmost one");
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
			wotsPlus.genKeyPair(privateKey.getWOTSPlusSecretKey(startIndex + i), otsHashAddress);
			lTreeAddress.setLTreeAddress(startIndex + i);
			XMSSNode node = lTree(lTreeAddress);
			hashTreeAddress.setTreeHeight(0);
			hashTreeAddress.setTreeIndex(startIndex + i);
			while(!stack.isEmpty() && stack.peek().getHeight() == node.getHeight()) {
				hashTreeAddress.setTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2);
				node = randomizeHash(stack.pop(), node, hashTreeAddress);
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
	private List<XMSSNode> buildAuthPath(OTSHashAddress address) {
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		int height = params.getHeight();
		int index = privateKey.getIndex();
		List<XMSSNode> authPath = new ArrayList<XMSSNode>();
		for (int i = 0; i < height; i++) {
			int k = ((int)Math.floor((double)index / (1 << i))) ^ 1;
			XMSSNode node = treeHash((k * (1 << i)), i, address, new LTreeAddress(), new HashTreeAddress());
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
	private XMSSSignature treeSig(byte[] messageDigest, OTSHashAddress address) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		/*
		 * recreate WOTS+ at index i. do not use the parameter address as during wots+ key
		 * generation certain attributes are changed.
		 */
		int index = privateKey.getIndex();
		OTSHashAddress tmpAddress = new OTSHashAddress();
		tmpAddress.setOTSAddress(privateKey.getIndex());
		wotsPlus.genKeyPair(privateKey.getWOTSPlusSecretKey(index), tmpAddress);
		
		/* create WOTS+ signature */
		address.setOTSAddress(privateKey.getIndex());
		WOTSPlusSignature wotsSignature = wotsPlus.sign(messageDigest, address);
		
		/* add authPath */
		List<XMSSNode> authPath = buildAuthPath(address);
		
		/* assemble temp signature */
		XMSSSignature tmpSignature = new XMSSSignature(wotsSignature.toByteArray(), authPath);
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
		XMSSSignature signature = treeSig(messageDigest, new OTSHashAddress());
		signature.setIndex(index);
		signature.setRandom(random);
		
		/* update index */
		privateKey.setIndex(index + 1);
		
		return signature;
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
