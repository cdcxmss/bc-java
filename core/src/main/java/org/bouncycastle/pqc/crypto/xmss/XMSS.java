package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

/**
 * XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSS {

	/**
	 * XMSS parameters.
	 */
	private XMSSParameters params;
	/**
	 * WOTS+ instance.
	 */
	protected WOTSPlus wotsPlus;
	/**
	 * PRNG.
	 */
	protected SecureRandom prng;
	/**
	 * Randomization functions.
	 */
	protected KeyedHashFunctions khf;
	/**
	 * XMSS private key.
	 */
	private XMSSPrivateKey privateKey;
	/**
	 * XMSS public key.
	 */
	private XMSSPublicKey publicKey;
	
	/**
	 * XMSS constructor...
	 * @param params XMSSParameters.
	 */
	public XMSS(XMSSParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
		wotsPlus = params.getWOTSPlus();
		prng = params.getPRNG();
		khf = wotsPlus.getKhf();
		privateKey = new XMSSPrivateKey(params);
		publicKey = new XMSSPublicKey(params);
	}
	
	/**
	 * Import keys.
	 * @param privateKey XMSS private key.
	 * @param publicKey XMSS public key.
	 */
	public void importKeys(byte[] privateKey, byte[] publicKey) throws ParseException {
		if (privateKey == null) {
			throw new NullPointerException("privateKey == null");
		}
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		XMSSPrivateKey tmpPrivateKey = new XMSSPrivateKey(params);
		tmpPrivateKey.parseByteArray(privateKey);
		XMSSPublicKey tmpPublicKey = new XMSSPublicKey(params);
		tmpPublicKey.parseByteArray(publicKey);
		if (!XMSSUtil.compareByteArray(tmpPrivateKey.getRoot(), tmpPublicKey.getRoot())) {
			throw new IllegalStateException("root of private key and public key do not match");
		}
		if (!XMSSUtil.compareByteArray(tmpPrivateKey.getPublicSeed(), tmpPublicKey.getPublicSeed())) {
			throw new IllegalStateException("publicSeed of private key and public key do not match");
		}
		this.privateKey = tmpPrivateKey;
		this.publicKey = tmpPublicKey;
		wotsPlus.importKeys(new byte[params.getDigestSize()], this.privateKey.getPublicSeed());
	}
	
	/**
	 * Generate new keys.
	 */
	public void generateKeys() {
		/* generate private key */
		privateKey = generatePrivateKey();
		wotsPlus.importKeys(new byte[params.getDigestSize()], privateKey.getPublicSeed());
		XMSSNode root = treeHash(0, params.getHeight(), new OTSHashAddress());
		privateKey.setRoot(root.getValue());
		
		/* generate public key */
		publicKey = new XMSSPublicKey(params);
		publicKey.setRoot(root.getValue());
		publicKey.setPublicSeed(getPublicSeed());
	}
	
	/**
	 * Generate an XMSS private key.
	 * @return XMSS private key.
	 */
	private XMSSPrivateKey generatePrivateKey() {
		int n = params.getDigestSize();
		byte[] publicSeed = new byte[n];
		prng.nextBytes(publicSeed);
		byte[] secretKeySeed = new byte[n];
		prng.nextBytes(secretKeySeed);
		byte[] secretKeyPRF = new byte[n];
		prng.nextBytes(secretKeyPRF);
		
		XMSSPrivateKey privateKey = new XMSSPrivateKey(params);
		privateKey.setPublicSeed(publicSeed);
		privateKey.setSecretKeySeed(secretKeySeed);
		privateKey.setSecretKeyPRF(secretKeyPRF);
		return privateKey;
	}
	
	/**
	 * Randomization of nodes in binary tree.
	 * @param left Left node.
	 * @param right Right node.
	 * @param hashTreeAddress Address.
	 * @return Randomized hash of parent of left / right node.
	 */
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
		byte[] publicSeed = getPublicSeed();
		address.setKeyAndMask(0);
		byte[] key = khf.PRF(publicSeed, address.toByteArray());
		address.setKeyAndMask(1);
		byte[] bitmask0 = khf.PRF(publicSeed, address.toByteArray());
		address.setKeyAndMask(2);
		byte[] bitmask1 = khf.PRF(publicSeed, address.toByteArray());
		int n = params.getDigestSize();
		byte[] tmpMask = new byte[2 * n];
		for (int i = 0; i < n; i++) {
			tmpMask[i] = (byte)(left.getValue()[i] ^ bitmask0[i]);
		}
		for (int i = 0; i < n; i++) {
			tmpMask[i+n] = (byte)(right.getValue()[i] ^ bitmask1[i]);
		}
		byte[] out = khf.H(key, tmpMask);
		return new XMSSNode(left.getHeight(), out);
	}
	
	/**
	 * Compresses a WOTS+ public key to a single n-byte string.
	 * @param publicKey WOTS+ public key to compress.
	 * @param address Address.
	 * @return Compressed n-byte string of public key.
	 */
	private XMSSNode lTree(WOTSPlusPublicKey publicKey, LTreeAddress address) {
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
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
				publicKeyNodes[i] = randomizeHash(publicKeyNodes[2 * i], publicKeyNodes[(2 * i) + 1], address);
			}
			if (len % 2 == 1) {
				publicKeyNodes[(int)Math.floor(len / 2)] = publicKeyNodes[len - 1];
			}
			len = (int)Math.ceil((double) len / 2);
			address.setTreeHeight(address.getTreeHeight() + 1);
		}
		return publicKeyNodes[0];
	}
	
	/**
	 * Calculate the root node of a tree of height targetNodeHeight.
	 * @param startIndex Start index.
	 * @param targetNodeHeight Height of tree.
	 * @param otsHashAddress OTS hash address.
	 * @param lTreeAddress LTree address.
	 * @param hashTreeAddress Hash tree address.
	 * @return Root node.
	 */
	protected XMSSNode treeHash(int startIndex, int targetNodeHeight, OTSHashAddress otsHashAddress) {
		if (startIndex % (1 << targetNodeHeight) != 0) {
			throw new IllegalArgumentException("leaf at index startIndex needs to be a leftmost one");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		
		/* prepare addresses */
		LTreeAddress lTreeAddress = new LTreeAddress();
		lTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
		lTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		hashTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
		hashTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());

		Stack<XMSSNode> stack = new Stack<XMSSNode>();
		for (int i = 0; i < (1 << targetNodeHeight); i++) {
			otsHashAddress.setOTSAddress(startIndex + i);
			wotsPlus.importKeys(getWOTSPlusSecretKey(otsHashAddress), getPublicSeed());
			WOTSPlusPublicKey wotsPlusPublicKey = wotsPlus.getPublicKey(otsHashAddress);
			lTreeAddress.setLTreeAddress(startIndex + i);
			XMSSNode node = lTree(wotsPlusPublicKey, lTreeAddress);
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
	 * Calculate the authentication path.
	 * @param address OTS hash address.
	 * @return Authentication path nodes.
	 */
	private List<XMSSNode> buildAuthPath(OTSHashAddress otsHashAddress) {
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		int treeHeight = params.getHeight();
		int indexOfPublicKey = privateKey.getIndex();
		List<XMSSNode> authPath = new ArrayList<XMSSNode>();
		
		for (int currentHeight = 0; currentHeight < treeHeight; currentHeight++) {
			int indexOfNodeOnHeight = ((int)Math.floor(indexOfPublicKey / (1 << currentHeight))) ^ 1;
			int startLeafIndex = (indexOfNodeOnHeight * (1 << currentHeight));
			XMSSNode node = treeHash(startLeafIndex, currentHeight, otsHashAddress);
			authPath.add(node);
		}
		return authPath;
	}
	
	/**
	 * Generate a WOTS+ signature on a message with corresponding authentication path
	 * @param messageDigest Message digest of length n.
	 * @param address OTS hash address.
	 * @return XMSS signature.
	 */
	protected XMSSSignature treeSig(byte[] messageDigest, OTSHashAddress address) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		/* create WOTS+ signature */
		WOTSPlusSignature wotsSignature = wotsPlus.sign(messageDigest, address);
		
		/* add authPath */
		List<XMSSNode> authPath = buildAuthPath(address);
		
		/* assemble temp signature */
		XMSSSignature tmpSignature = new XMSSSignature(params);
		tmpSignature.setSignature(wotsSignature);
		tmpSignature.setAuthPath(authPath);
		return tmpSignature;
	}

	/**
	 * Sign message.
	 * @param message Message to sign.
	 * @return XMSS signature on digest of message.
	 */
	public byte[] sign(byte[] message) {
		int index = privateKey.getIndex();
		if (!XMSSUtil.isIndexValid(getParams().getHeight(), index)) {
			throw new IllegalArgumentException("index out of bounds");
		}
		/* reinitialize WOTS+ object */
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setOTSAddress(index);
		
		wotsPlus.importKeys(getWOTSPlusSecretKey(otsHashAddress), getPublicSeed());

		/* create (randomized keyed) messageDigest of message */
		byte[] random = khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(index, 32));
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		/* create signature for messageDigest */
		XMSSSignature signature = treeSig(messageDigest, otsHashAddress);
		signature.setIndex(index);
		signature.setRandom(random);
		
		/* update index */
		privateKey.setIndex(index + 1);

		return signature.toByteArray();
	}
	
	/**
	 * Compute a root node from a tree signature.
	 * @param messageDigest Message digest.
	 * @param signature XMSS signature.
	 * @return Root node calculated from signature.
	 */
	protected XMSSNode getRootNodeFromSignature(byte[] messageDigest, XMSSReducedSignature signature, OTSHashAddress otsHashAddress) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (otsHashAddress == null) {
			throw new NullPointerException("otsHashAddress == null");
		}
		
		/* prepare adresses */
		LTreeAddress lTreeAddress = new LTreeAddress();
		lTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
		lTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
		lTreeAddress.setLTreeAddress(otsHashAddress.getOTSAddress());
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		hashTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
		hashTreeAddress.setTreeAddress(otsHashAddress.getTreeAddress());
		hashTreeAddress.setTreeIndex(otsHashAddress.getOTSAddress());
		
		/* calculate WOTS+ public key and compress to obtain original leaf hash */
		WOTSPlusPublicKey wotsPlusPK = wotsPlus.getPublicKeyFromSignature(messageDigest, signature.getSignature(), otsHashAddress);
		XMSSNode[] node = new XMSSNode[2];
		node[0] = lTree(wotsPlusPK, lTreeAddress);
		
		for (int k = 0; k < params.getHeight(); k++){
			hashTreeAddress.setTreeHeight(k);
			if (Math.floor(privateKey.getIndex() / (1 << k)) % 2 == 0) {
				hashTreeAddress.setTreeIndex(hashTreeAddress.getTreeIndex() / 2);
				node[1] = randomizeHash(node[0], signature.getAuthPath().get(k), hashTreeAddress);
				node[1].setHeight(node[1].getHeight() + 1);
			} else {
				hashTreeAddress.setTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2);
				node[1] = randomizeHash(signature.getAuthPath().get(k), node[0], hashTreeAddress);
				node[1].setHeight(node[1].getHeight() + 1);
			}
			node[0] = node[1];
		}
		return node[0];
	}
	
	/**
	 * Verify an XMSS signature using the corresponding XMSS public key and a message.
	 * @param message Message.
	 * @param signature XMSS signature.
	 * @param publicKey XMSS public key.
	 * @return true if signature is valid false else.
	 */
	public boolean verifySignature(byte[] message, byte[] sig, byte[] pubKey) throws ParseException {
		if (message == null) {
			throw new NullPointerException("message == null");
		}
		if (sig == null) {
			throw new NullPointerException("signature == null");
		}
		if (pubKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		/* parse signature and public key */
		XMSSSignature signature = new XMSSSignature(params);
		signature.parseByteArray(sig);
		XMSSPublicKey publicKey = new XMSSPublicKey(params);
		publicKey.parseByteArray(pubKey);

		/* set index */
		int index = signature.getIndex();
		int currentIndex = privateKey.getIndex();
		setIndex(index);

		/* reinitialize WOTS+ object */
		byte[] publicSeed = publicKey.getPublicSeed();
		wotsPlus.importKeys(new byte[params.getDigestSize()], publicSeed);
		
		/* create message digest */
		byte[] concatenated = XMSSUtil.concat(signature.getRandom(), publicKey.getRoot(), XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		/* create addresses */
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setOTSAddress(index);
		
		/* get root from signature */
		XMSSNode rootNodeFromSignature = getRootNodeFromSignature(messageDigest, signature, otsHashAddress);
		
		/* reset index */
		setIndex(currentIndex);
		return XMSSUtil.compareByteArray(rootNodeFromSignature.getValue(), publicKey.getRoot());
	}
	
	/**
	 * Derive WOTS+ secret key for specific index according to draft.
	 * @param index Index.
	 * @return WOTS+ secret key at index.
	 */
	protected byte[] getWOTSPlusSecretKey(int index) {
		return khf.PRF(privateKey.getSecretKeySeed(), XMSSUtil.toBytesBigEndian(index, 32));
	}
	
	/**
	 * Derive WOTS+ secret key for specific index as in XMSS ref impl Andreas Huelsing.
	 * @param index Index.
	 * @return WOTS+ secret key at index.
	 */
	protected byte[] getWOTSPlusSecretKey(OTSHashAddress otsHashAddress) {
		otsHashAddress.setChainAddress(0);
		otsHashAddress.setHashAddress(0);
		otsHashAddress.setKeyAndMask(0);
		return khf.PRF(privateKey.getSecretKeySeed(), otsHashAddress.toByteArray());
	}
	
	/**
	 * Getter XMSS params.
	 * @return XMSS params.
	 */
	public XMSSParameters getParams() {
		return params;
	}
	
	/**
	 * Getter WOTS+.
	 * @return WOTS+ instance.
	 */
	protected WOTSPlus getWOTSPlus() {
		return wotsPlus;
	}
	
	/**
	 * Getter Root.
	 * @return Root of binary tree.
	 */
	public byte[] getRoot() {
		return privateKey.getRoot();
	}
	
	protected void setRoot(byte[] root) {
		privateKey.setRoot(root);
		publicKey.setRoot(root);
	}
	
	/**
	 * Getter index.
	 * @return Index.
	 */
	public long getIndex() {
		return privateKey.getIndex();
	}
	
	protected void setIndex(long index) {
		privateKey.setIndex((int)index);
	}
	
	/**
	 * Getter public seed.
	 * @return Public seed.
	 */
	protected byte[] getPublicSeed() {
		return wotsPlus.getPublicSeed();
	}
	
	/**
	 * Getter private key.
	 * @return XMSS private key.
	 */
	public byte[] getPrivateKey() {
		return privateKey.toByteArray();
    }

	/**
	 * Getter public key.
	 * @return XMSS public key.
	 */
	public byte[] getPublicKey() {
		return publicKey.toByteArray();
	}
}
