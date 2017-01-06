package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;


/**
 * Multi-Tree XMSS 
 * As described in https://tools.ietf.org/html/draft-irtf-cfrg-xmss-hash-based-signatures-07#section-4.2
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 *
 */
public class XMSSMT extends XMSS{
	
	/**
	 * XMSSMT parameters.
	 */
	private XMSSMTParameters params;
	
	/**
	 * XMSSMT private key.
	 */
	private XMSSMTPrivateKey privateKey;
	
	/**
	 * XMSSMT public key.
	 */
	private XMSSMTPublicKey publicKey;
	
	byte[] root;
	

	/**
	 * XMSSMT constructor...
	 * @param params {@link XMSSMTParameters}.
	 */
	public XMSSMT(XMSSMTParameters params) {
		super(new XMSSParameters(params.getHeight(), params.getDigest(), params.getPRNG()));
		this.params = params;
		publicSeed = new byte[params.getDigestSize()];
		params.getPRNG().nextBytes(publicSeed);
		khf = new KeyedHashFunctions(params.getDigest(), params.getDigestSize());
	}
	
	/**
	 * Calculates an {@link XMSSMTPrivateKey} and an {@link XMSSMTPublicKey}.
	 */
	@Override
	public void generateKeys(){
		privateKey = new XMSSMTPrivateKey(params);
		int layerAddress = params.getLayers() - 1;
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		otsHashAddress.setLayerAddress(layerAddress);
		lTreeAddress.setLayerAddress(layerAddress);
		hashTreeAddress.setLayerAddress(layerAddress);
		XMSSNode root = treeHash(privateKey.getSecretKeySeed(), privateKey.getPublicSeed(), 0, params.getHeight(), otsHashAddress, lTreeAddress, hashTreeAddress);
		privateKey.setRoot(root.getValue());
		publicKey = new XMSSMTPublicKey(this);
		publicKey.setRoot(root.getValue());
	}
	
	/**
	 * Import keys.
	 * @param privateKey {@link XMSSMTPrivateKey}.
	 * @param publicKey {@link XMSSMTPublicKey}.
	 */
	@Override
	public void importKeys(byte[] privateKey, byte[] publicKey) throws ParseException {
		if (privateKey == null) {
			throw new NullPointerException("privateKey == null");
		}
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		XMSSMTPrivateKey tmpPrivateKey = new XMSSMTPrivateKey(params);
		tmpPrivateKey.parseByteArray(privateKey);
		XMSSMTPublicKey tmpPublicKey = new XMSSMTPublicKey(this);
		tmpPublicKey.parseByteArray(publicKey);
		if (!XMSSUtil.compareByteArray(tmpPrivateKey.getRoot(), tmpPublicKey.getRoot())) {
			throw new IllegalStateException("root of private key and public key do not match");
		}
		if (!XMSSUtil.compareByteArray(tmpPrivateKey.getPublicSeed(), tmpPublicKey.getPublicSeed())) {
			throw new IllegalStateException("publicSeed of private key and public key do not match");
		}
		this.privateKey = tmpPrivateKey;
		this.publicKey = tmpPublicKey;
		this.publicSeed = this.publicKey.getPublicSeed();
	}
	
	/**
	 * Generate an {@link XMSSMTSignature} and update the {@link XMSSMTPrivateKey}
	 * @param message the message to be signed
	 * @return {@link XMSSMTSignature} as byte array
	 */
	public byte[] signMT(byte[] message){
		XMSSMTSignature signature = new XMSSMTSignature(params);
		int index = privateKey.getIndex();
		signature.setIndex(index);
		// Init addresses
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		otsHashAddress.setLayerAddress(0);
		lTreeAddress.setLayerAddress(0);
		hashTreeAddress.setLayerAddress(0);
		
		//update sk
		privateKey.setIndex(index + 1);
		
		//message compression
		byte[] random =  khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(signature.getIndex(), 32));
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		//Sign
		int indexTree = index >> params.getHeight();
		int indexLeaf = index & ((1 << params.getHeight()) - 1);
		otsHashAddress.setTreeAddress(indexTree);
		lTreeAddress.setTreeAddress(indexTree);
		hashTreeAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		byte[] secretSeed = getSeed(privateKey.getSecretKeySeed(), otsHashAddress);
		wotsPlus.importKeys(secretSeed, publicSeed);
		ReducedXMSSSignature sigTmp = treeSig(indexLeaf, messageDigest, privateKey.getSecretKeySeed(), privateKey.getPublicSeed(), otsHashAddress);
		signature.setRandomness(random);
		signature.addReducedSignature(sigTmp);
		
		// Now loop over remaining layers...
		for (int j = 1; j < params.getLayers(); j++) {
			// Prepare Address
			indexLeaf = indexTree & ((1 << params.getHeight()) - 1);
			indexTree = indexTree >> params.getHeight();
			otsHashAddress.setLayerAddress(j);
			otsHashAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			// Compute WOTS signature
			
			secretSeed = getSeed(privateKey.getSecretKeySeed(), otsHashAddress);
			wotsPlus.importKeys(secretSeed, publicSeed);
			sigTmp = treeSig(indexLeaf, root, privateKey.getSecretKeySeed(), privateKey.getPublicSeed(), otsHashAddress);
			signature.addReducedSignature(sigTmp);
		}
		
		return signature.toByteArray();
	}
	
	/**
	 * Verify an {@link XMSSMTSignature} on a message using the {@link XMSSMTPublicKey} of this instance.
	 * @param {@link XMSSMTSignature} signature
	 * @param message
	 * @return true if and only if signature is a valid {@link XMSSMTSignature} on the message under this {@link XMSSMTPublicKey}.  Otherwise, it returns false.
	 * @throws ParseException 
	 */
	public boolean verifyMT(byte[] signature, byte[] message) throws ParseException {
		// Init addresses
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		otsHashAddress.setLayerAddress(0);
		lTreeAddress.setLayerAddress(0);
		hashTreeAddress.setLayerAddress(0);
		XMSSMTSignature sig = new XMSSMTSignature(params);
		sig.parseByteArray(signature);
		int  index = sig.getIndex();
		int height = params.getHeight();
		int totalHeight = params.getTotalHeight();
		int layers = params.getLayers();
		byte[] concatenated = XMSSUtil.concat(sig.getRandomness(), publicKey.getRoot(), XMSSUtil.toBytesBigEndian(sig.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		int indexTree = XMSSUtil.getMSB(index, totalHeight - height, totalHeight);
		int indexLeaf = XMSSUtil.getLSB(index, height, totalHeight);
		otsHashAddress.setTreeAddress(indexTree);
		lTreeAddress.setTreeAddress(indexTree);
		hashTreeAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		ReducedXMSSSignature xmssSig = sig.getReducedSignature(0);
		XMSSNode node = getRootNodeFromSignature(indexLeaf, messageDigest, xmssSig, publicSeed, otsHashAddress, lTreeAddress, hashTreeAddress);
		for (int j = 1; j < layers; j++) {
			indexTree = XMSSUtil.getMSB(indexTree, totalHeight - height, totalHeight);
			indexLeaf =  XMSSUtil.getLSB(indexTree, height, totalHeight);
			xmssSig = sig.getReducedSignature(j);
			otsHashAddress = new OTSHashAddress();
			otsHashAddress.setLayerAddress(j);
			lTreeAddress = new LTreeAddress();
			lTreeAddress.setLayerAddress(j);
			hashTreeAddress.setLayerAddress(j);
			otsHashAddress.setTreeAddress(indexTree);
			lTreeAddress.setTreeAddress(indexTree);
			hashTreeAddress.setTreeAddress(indexTree);
			node = getRootNodeFromSignature(indexLeaf, node.getValue(), xmssSig, publicSeed, otsHashAddress, lTreeAddress, hashTreeAddress);
		}
		if (Arrays.equals(node.getValue(), publicKey.getRoot())) {
			return true;
		}
		return false;
	}
	
	/**
	 * Generate a WOTS+ signature on a message with corresponding authentication path
	 * @param index 
	 * @param messageDigest Message digest of length n.
	 * @param address OTS hash address.
	 * @return Temporary signature.
	 */
	protected ReducedXMSSSignature treeSig(int index, byte[] messageDigest, byte[] skSeed, byte[] pkSeed, OTSHashAddress address) {
		if (messageDigest.length != params.getDigestSize()) {
			throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
		}
		if (address == null) {
			throw new NullPointerException("address == null");
		}
		
		/* create WOTS+ signature */
		address.setOTSAddress(index);
		WOTSPlusSignature wotsSignature = wotsPlus.sign(messageDigest, pkSeed, address);
		/* add authPath */
		List<XMSSNode> authPath = buildAuthPath(index, address, skSeed, pkSeed);
		/* assemble temp signature */
		ReducedXMSSSignature tmpSignature = new ReducedXMSSSignature(this);
		tmpSignature.setSignature(wotsSignature);
		tmpSignature.setAuthPath(authPath);
		return tmpSignature;
	}
	
	/**
	 * Calculate the authentication path and sets the root node.
	 * The method buildAuthPath is based on Andreas Huelsing's compute_authpath_wots from xmss.c in http://www.huelsing.net/code/xmss_ref_20160722.tar.gz
	 * @param index
	 * @param address OTS hash address.
	 * @param seed
	 * @return Authentication path nodes.
	 */
	protected List<XMSSNode> buildAuthPath(int index, OTSHashAddress otsAddress, byte[] skSeed, byte[] pkSeed) {
		if (otsAddress == null) {
			throw new NullPointerException("address == null");
		}
		int treeHeight = params.getHeight();
		//work around otherwise have to have all addresses as parameter
		OTSHashAddress otsHashAddress = otsAddress;
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress nodeAddr = new HashTreeAddress();
		lTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
		nodeAddr.setLayerAddress(otsHashAddress.getLayerAddress());
		
		// Compute all leaves
		byte[][] tree = new byte[2 * (1<<treeHeight)][];
		for (int i = 0; i < (1 << treeHeight); i++) {
		  lTreeAddress.setLTreeAddress(i);
		  otsHashAddress.setOTSAddress(i);
		  byte[] seed = getSeed(skSeed, otsHashAddress);
		  WOTSPlusPublicKey wotsPK = wotsPlus.getPublicKey(otsHashAddress, seed, pkSeed);
		  XMSSNode leaf = lTree(wotsPK, pkSeed, lTreeAddress);
		  tree[(1<<treeHeight)+i] = leaf.getValue();
		}
		
		List<XMSSNode> authpath = new ArrayList<XMSSNode>();
		int level = 0;
		// Compute tree:
		// Outer loop: For each inner layer
		for (int i = (1 << treeHeight); i > 1; i>>=1){
			nodeAddr.setTreeHeight(level);
			// Inner loop: for each pair of sibling nodes
			for (int j = 0; j < i; j+=2){
				nodeAddr.setTreeIndex(j>>1);
				byte[] treeConcat = XMSSUtil.concat(tree[i + j], tree[i + j + 1]);
				byte[] hash = khf.H(treeConcat, pkSeed, nodeAddr);
				tree[(i>>1) + (j>>1)] = hash;
			}
			level++;
		}
		
		//tree[0] is not set in reference it is just 0.
		//here it is null and causes problems so we set it manually to 0.
		tree[0] = new byte[params.getDigestSize()];
		
//		copy authpath
		for (int i = 0; i < treeHeight; i++){
			int treeIndex = (1<<treeHeight)>>i;
			int leafIndex = (index >> i) ^1;
			byte[] nodeBytes = tree[treeIndex+leafIndex];
			XMSSNode node = new XMSSNode(i, nodeBytes);
			authpath.add(node);
		}
		
		root = tree[1];
		
		return authpath;
		
	}
	
	/**
	 * Calculate the root node of a tree of height targetNodeHeight.
	 * @param skSeed the secret key seed
	 * @param startIndex Start index.
	 * @param targetNodeHeight Height of tree.
	 * @param otsHashAddress OTS hash address.
	 * @param lTreeAddress LTree address.
	 * @param hashTreeAddress Hash tree address.
	 * @return Root node.
	 */
	protected XMSSNode treeHash(byte[] skSeed, byte[] publicSeed, int startIndex, int targetNodeHeight, OTSHashAddress otsHashAddress, LTreeAddress lTreeAddress, HashTreeAddress hashTreeAddress) {
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
		List<XMSSNode> stack = new ArrayList<XMSSNode>();
		int stackOffset = 0;
		int[] stackLevels = new int[targetNodeHeight + 1];
		for (int i = startIndex; i < startIndex + (1 << targetNodeHeight); i++) {
			lTreeAddress.setLTreeAddress(i);
			otsHashAddress.setOTSAddress(i);
			byte[] seed = getSeed(skSeed, otsHashAddress);
			WOTSPlusPublicKey wotsPK = wotsPlus.getPublicKey(otsHashAddress, seed, publicSeed);
			XMSSNode node = lTree(wotsPK, publicSeed, lTreeAddress);
			if (stack.size() > stackOffset){
				stack.set(stackOffset, node);
			} else {
				stack.add(node);
			}
			stackLevels[stackOffset] = 0;
			stackOffset++;
			while(stackOffset > 1 && stackLevels[stackOffset - 1] == stackLevels[stackOffset - 2]) {
				hashTreeAddress.setTreeHeight(stackLevels[stackOffset - 1]);
				int treeIndex = i >> (stackLevels[stackOffset - 1] + 1);
				hashTreeAddress.setTreeIndex(treeIndex);
				byte[] stackConcat = XMSSUtil.concat(stack.get(stackOffset - 2).getValue(), stack.get(stackOffset - 1).getValue());
				byte[] newNode = khf.H(stackConcat, publicSeed, hashTreeAddress);
				XMSSNode newXmssNode = new XMSSNode(stackLevels[stackOffset - 2]++, newNode);
				stack.remove(stackOffset - 2);
				stack.add(stackOffset - 2, newXmssNode);
				stackOffset--;
			}
		}
		return stack.get(0);
	}
	
	public XMSSMTParameters getParams() {
		return params;
	}

	public XMSSMTPrivateKey getXMSSMTPrivateKey() {
		return privateKey;
	}
	
	public XMSSMTPublicKey getXMSSMTPublicKey() {
		return publicKey;
	}
	
	public byte[] getPrivateKey() {
		return privateKey.toByteArray();
	}

	public byte[] getPublicKey() {
		return publicKey.toByteArray();
	}
	
}
