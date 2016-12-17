package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Stack;


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
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
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
	@Override
	public byte[] sign(byte[] message){
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
		
		byte[] random =  khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
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
		ReducedXMSSSignature sigTmp = treeSig(indexLeaf, messageDigest, privateKey.getSecretKeySeed(), privateKey.getPublicSeed(), otsHashAddress);//secretSeed
		signature.setRandomness(random);
		signature.addReducedSignature(sigTmp);
		
		// Now loop over remaining layers...
		for (int j = 1; j < params.getLayers(); j++) {
			System.out.println("j = " + j);
			// Prepare Address
//			XMSSNode root = treeHash(privateKey.getSecretKeySeed(), privateKey.getPublicSeed(), 0, params.getHeight(), otsHashAddress, lTreeAddress, hashTreeAddress);//secretSeed
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
	
//	/**
//	 * Used for pseudorandom keygeneration,
//	 * generates the seed for the WOTS keypair at address
//	 * @param skSeed the secret seed
//	 * @param otsHashAddress
//	 * @return n-byte seed using 32 byte address addr.
//	 */
//	public byte[] getSeed(byte[] skSeed, OTSHashAddress otsHashAddress) {
//		// Make sure that chain addr, hash addr, and key bit are 0!
//		otsHashAddress.setChainAddress(0);
//		otsHashAddress.setHashAddress(0);
//		otsHashAddress.setKeyAndMask(0);
//		// Generate pseudorandom value
//		return khf.PRF(skSeed, otsHashAddress.toByteArray());
//	}
//	
	/**
	 * Verify an {@link XMSSMTSignature} on a message using the {@link XMSSMTPublicKey} of this instance.
	 * @param {@link XMSSMTSignature} signature
	 * @param message
	 * @return true if and only if signature is a valid {@link XMSSMTSignature} on the message under this {@link XMSSMTPublicKey}.  Otherwise, it returns false.
	 * @throws ParseException 
	 */
	public boolean verify(byte[] signature, byte[] message) throws ParseException {
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
		WOTSPlusSignature wotsSignature = wotsPlus.sign(messageDigest, pkSeed, address);//after this hash =0 not 10
		/* add authPath */
		List<XMSSNode> authPath = buildAuthPath(index, address, skSeed, pkSeed);//new address as param -> no as param new in method
//		String authpath0 = adapter.marshal(authPath.get(0).getValue());
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
		OTSHashAddress otsHashAddress = otsAddress;//new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress nodeAddr = new HashTreeAddress();
		lTreeAddress.setLayerAddress(otsHashAddress.getLayerAddress());
		nodeAddr.setLayerAddress(otsHashAddress.getLayerAddress());
		int digestSize = params.getDigestSize();
		
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
		tree[0] = new byte[32];
		
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
	
	private XMSSNode treeHash(int treeHeight, OTSHashAddress otsHashAddress, LTreeAddress lTreeAddress, HashTreeAddress nodeAddr, byte[] skSeed, byte[] pkSeed){
		List<XMSSNode> leaves = new ArrayList<XMSSNode>();
		Stack<XMSSNode> stack = new Stack<XMSSNode>();
		for (int i = 0; i < (1 << treeHeight); i++) {
		  lTreeAddress.setLTreeAddress(i);
		  otsHashAddress.setOTSAddress(i);
		  byte[] seed = getSeed(skSeed, otsHashAddress);
		  WOTSPlusPublicKey wotsPK = wotsPlus.getPublicKey(otsHashAddress, seed, pkSeed);
		  XMSSNode leaf = lTree(wotsPK, pkSeed, lTreeAddress);
		  leaves.add(leaf);
		  while(!stack.isEmpty() && stack.peek().getHeight() == leaf.getHeight()) {
			  	nodeAddr.setTreeIndex((nodeAddr.getTreeIndex() - 1) / 2);
				leaf = randomizeHash(stack.pop(), leaf, seed, nodeAddr);
				leaf.setHeight(leaf.getHeight() + 1);
				nodeAddr.setTreeHeight(nodeAddr.getTreeHeight() + 1);
			}
			stack.push(leaf);
		}
		return stack.pop();
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
	
	private byte[] getWOTSPlusSecretKey(int x, int y, int index){
		/* Find the array index of the relevant reduced key */
		int count = -1;
		for (int j = params.getLayers() ; j > y + 1; j--) {
			count += (1 << (params.getTotalHeight() - j * params.getHeight()));
		}
		count += x + 1;
		return khf.PRF(khf.PRF(privateKey.getSecretKeySeed(), XMSSUtil.toBytesBigEndian(count, 32)), XMSSUtil.toBytesBigEndian(index, 32));
	}
	
}
