package org.bouncycastle.pqc.crypto.xmss;

import java.util.Stack;

/**
 * XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSS {

	private XMSSParameters params;
	private WinternitzOTSPlus wotsPlus;
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
		WinternitzOTSPlusParameters wotsPlusParams = new WinternitzOTSPlusParameters(params.getDigest(), params.getPRNG());
		wotsPlus = new WinternitzOTSPlus(wotsPlusParams, publicSeed);
		stack = new Stack<XMSSNode>();
	}
	
	public void genKeyPair() {
		privateKey = new XMSSPrivateKey(this);
		XMSSNode root = treeHash(0, params.getHeight());
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
		byte[][] publicKey = wotsPlus.getPublicKey();
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
	
	private XMSSNode treeHash(int startIndex, int targetNodeHeight) {
		if (startIndex % (1 << targetNodeHeight) != 0) {
			throw new IllegalArgumentException("leaf at index startIndex needs to be a leftmost one");
		}
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
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
	
	public XMSSParameters getParams() {
		return params;
	}
	
	public byte[] getPublicSeed() {
		return publicSeed;
	}
	
	public XMSSPublicKey getPublicKey() {
		return publicKey;
	}
	
	public XMSSPrivateKey getPrivateKey() {
		return privateKey;
	}
}
