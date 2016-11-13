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
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSS {

	/**
	 * XMSS parameters.
	 */
	private XMSSParameters params;
	/**
	 * WOTS+ instance.
	 */
	private WOTSPlus wotsPlus;
	/**
	 * PRNG.
	 */
	private SecureRandom prng;
	/**
	 * Randomization functions.
	 */
	private KeyedHashFunctions khf;
	/**
	 * XMSS / WOTS+ public seed.
	 */
	private byte[] publicSeed;
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
	public XMSS(XMSSParameters params, SecureRandom prng) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		if (prng == null) {
			throw new NullPointerException("prng == null");
		}
		this.params = params;
		wotsPlus = new WOTSPlus(new WOTSPlusParameters(params.getDigest(), params.getWinternitzParameter()), prng);
		this.prng = prng;
		khf = new KeyedHashFunctions(params.getDigest());
	}
	
	/**
	 * Import keys.
	 * @param privateKey XMSS private key.
	 * @param publicKey XMSS public key.
	 */
	public void importKeys(byte[] privateKey, byte[] publicKey) {
		if (privateKey == null) {
			throw new NullPointerException("privateKey == null");
		}
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		XMSSPrivateKey tmpPrivateKey = new XMSSPrivateKey(this);
		try {
			tmpPrivateKey.parseByteArray(privateKey);
		} catch (ParseException ex) {
			ex.printStackTrace();
		}
		XMSSPublicKey tmpPublicKey = new XMSSPublicKey(this);
		try {
			tmpPublicKey.parseByteArray(publicKey);
		} catch (ParseException ex) {
			ex.printStackTrace();
		}
		if (!XMSSUtil.compareByteArray(tmpPrivateKey.getRoot(), tmpPublicKey.getRoot())) {
			throw new IllegalStateException("root of private key and public key do not match");
		}
		if (!XMSSUtil.compareByteArray(tmpPrivateKey.getPublicSeed(), tmpPublicKey.getPublicSeed())) {
			throw new IllegalStateException("publicSeed of private key and public key do not match");
		}
		this.privateKey = tmpPrivateKey;
		this.publicKey = tmpPublicKey;
		this.publicSeed = this.privateKey.getPublicSeed();
	}
	
	/**
	 * Generate new keys.
	 */
	public void generateKeys() {
		publicSeed = new byte[params.getDigestSize()];
		prng.nextBytes(publicSeed);
		privateKey = generatePrivateKey();
		XMSSNode root = treeHash(0, params.getHeight(), new OTSHashAddress(), new LTreeAddress(), new HashTreeAddress());
		privateKey.setRoot(root.getValue());
		publicKey = new XMSSPublicKey(this);
		publicKey.setOid(params.getOid().getOid());
		publicKey.setRoot(root.getValue());
		publicKey.setPublicSeed(publicSeed);
	}
	
	/**
	 * Generate an XMSS private key.
	 * @return XMSS private key.
	 */
	private XMSSPrivateKey generatePrivateKey() {
		int n = getParams().getDigestSize();
		byte[] secretKeySeed = new byte[n];
		prng.nextBytes(secretKeySeed);
		byte[] secretKeyPRF = new byte[n];
		prng.nextBytes(secretKeyPRF);
		
		XMSSPrivateKey privateKey = new XMSSPrivateKey(this);
		privateKey.setPublicSeed(publicSeed);
		privateKey.setSecretKeySeed(secretKeySeed);
		privateKey.setSecretKeyPRF(secretKeyPRF);
		return privateKey;
	}
	
	/**
	 * Randomization of nodes in binary tree.
	 * @param left Left node.
	 * @param right Right node.
	 * @param publicSeed Public seed for randomization purposes.
	 * @param address Address.
	 * @return Randomized hash of parent of left / right node.
	 */
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
	 * @param publicSeed Public seed.
	 * @param address Address.
	 * @return Compressed n-byte string of public key.
	 */
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
	
	/**
	 * Calculate the root node of a tree of height targetNodeHeight.
	 * @param startIndex Start index.
	 * @param targetNodeHeight Height of tree.
	 * @param otsHashAddress OTS hash address.
	 * @param lTreeAddress LTree address.
	 * @param hashTreeAddress Hash tree address.
	 * @return Root node.
	 */
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
		Stack<XMSSNode> stack = new Stack<XMSSNode>();
		for (int i = 0; i < (1 << targetNodeHeight); i++) {
			wotsPlus.importKeys(getWOTSPlusSecretKey(startIndex + i), publicSeed);
			otsHashAddress.setOTSAddress(startIndex + i);
			lTreeAddress.setLTreeAddress(startIndex + i);
			XMSSNode node = lTree(wotsPlus.getPublicKey(otsHashAddress), publicSeed, lTreeAddress);
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
	 * Calculate the authentication path.
	 * @param address OTS hash address.
	 * @return Authentication path nodes.
	 */
	private List<XMSSNode> buildAuthPath(OTSHashAddress address) {
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		int treeHeight = params.getHeight();
		int indexOfPublicKey = privateKey.getIndex();
		List<XMSSNode> authPath = new ArrayList<XMSSNode>();
		for (int currentHeight = 0; currentHeight < treeHeight; currentHeight++) {
			int indexOfNodeOnHeight = ((int)Math.floor(indexOfPublicKey / (1 << currentHeight))) ^ 1;
			int startLeafIndex = (indexOfNodeOnHeight * (1 << currentHeight));
			XMSSNode node = treeHash(startLeafIndex, currentHeight, address, new LTreeAddress(), new HashTreeAddress());
			authPath.add(node);
		}
		return authPath;
	}
	
	/**
	 * Generate a WOTS+ signature on a message with corresponding authentication path
	 * @param messageDigest Message digest of length n.
	 * @param address OTS hash address.
	 * @return Temporary signature.
	 */
	private XMSSSignature treeSig(byte[] messageDigest, OTSHashAddress address) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}	
		/* create WOTS+ signature */
		address.setOTSAddress(privateKey.getIndex());
		WOTSPlusSignature wotsSignature = wotsPlus.sign(messageDigest, address);
		
		/* add authPath */
		List<XMSSNode> authPath = buildAuthPath(address);
		
		/* assemble temp signature */
		XMSSSignature tmpSignature = new XMSSSignature(this);
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
		checkState();
		/* reinitialize WOTS+ object */
		int index = privateKey.getIndex();
		wotsPlus.importKeys(getWOTSPlusSecretKey(index), publicSeed);

		/* create (randomized keyed) messageDigest of message */
		byte[] random = khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(index, 32));
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		/* create signature for messageDigest */
		XMSSSignature signature = treeSig(messageDigest, new OTSHashAddress());
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
	 * @param publicSeed Public seed.
	 * @return Root node calculated from signature.
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
		WOTSPlusPublicKey wotsPlusPK = wotsPlus.getPublicKeyFromSignature(messageDigest, signature.getSignature(), otsHashAddress);
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
	 * Verify an XMSS signature using the corresponding XMSS public key and a message.
	 * @param message Message.
	 * @param signature XMSS signature.
	 * @param publicKey XMSS public key.
	 * @return true if signature is valid false else.
	 */
	public boolean verifySignature(byte[] message, byte[] sig, byte[] pubKey) {
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
		XMSSSignature signature = new XMSSSignature(this);
		try {
			signature.parseByteArray(sig);
		} catch (ParseException ex) {
			ex.printStackTrace();
		}
		XMSSPublicKey publicKey = new XMSSPublicKey(this);
		try {
			publicKey.parseByteArray(pubKey);
		} catch (ParseException ex) {
			ex.printStackTrace();
		}
		/* reinitialize WOTS+ object */
		int index = signature.getIndex();
		byte[] publicSeed = publicKey.getPublicSeed();
		wotsPlus.importKeys(new byte[params.getDigestSize()], publicSeed);
		
		/* create message digest */
		byte[] concatenated = XMSSUtil.concat(signature.getRandom(), publicKey.getRoot(), XMSSUtil.toBytesBigEndian(index, params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		XMSSNode rootNodeFromSignature = getRootNodeFromSignature(messageDigest, signature, publicKey.getPublicSeed());
		return XMSSUtil.compareByteArray(rootNodeFromSignature.getValue(), publicKey.getRoot());
	}
	
	/**
	 * Derive WOTS+ secret key for specific index.
	 * @param index Index.
	 * @return WOTS+ secret key at index.
	 */
	private byte[] getWOTSPlusSecretKey(int index) {
		return khf.PRF(privateKey.getSecretKeySeed(), XMSSUtil.toBytesBigEndian(index, 32));
	}
	
	/**
	 * Check whether keys are available.
	 */
	private void checkState() {
		if (privateKey == null || publicKey == null || publicSeed == null) {
			throw new IllegalStateException("not initialized");
		}
	}

	/**
	 * Getter XMSS params.
	 * @return XMSS params.
	 */
	public XMSSParameters getParams() {
		return params;
	}
	
	protected WOTSPlus getWOTSPlus() {
		return wotsPlus;
	}
	
	/**
	 * Getter public seed.
	 * @return Public seed.
	 */
	protected byte[] getPublicSeed() {
		if (publicSeed == null) {
			throw new IllegalStateException("not initialized");
		}
		return publicSeed;
	}
	
	/**
	 * Getter private key.
	 * @return XMSS private key.
	 */
	public byte[] getPrivateKey() {
		if (privateKey == null) {
			throw new IllegalStateException("not initialized");
		}
		return privateKey.toByteArray();
    }

	/**
	 * Getter public key.
	 * @return XMSS public key.
	 */
	public byte[] getPublicKey() {
		if (publicKey == null) {
			throw new IllegalStateException("not initialized");
		}
		return publicKey.toByteArray();
	}
}
