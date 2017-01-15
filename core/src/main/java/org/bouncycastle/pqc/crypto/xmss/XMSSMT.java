package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * Multi-Tree XMSS 
 * As described in https://tools.ietf.org/html/draft-irtf-cfrg-xmss-hash-based-signatures-07#section-4.2
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 *
 */
public class XMSSMT extends XMSS {
	
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
	

	/**
	 * XMSSMT constructor...
	 * @param params {@link XMSSMTParameters}.
	 */
	public XMSSMT(XMSSMTParameters params) {
		super(new XMSSParameters(params.getHeight(), params.getDigest(), params.getPRNG()));
		this.params = params;
	}
	
	/**
	 * Calculates an {@link XMSSMTPrivateKey} and an {@link XMSSMTPublicKey}.
	 */
	@Override
	public void generateKeys() {
		/* generate private key */
		privateKey = generatePrivateKey();
		
		/* init global xmss */
		XMSSPrivateKey xmssPrivateKey = new XMSSPrivateKey(params);
		xmssPrivateKey.setSecretKeySeed(privateKey.getSecretKeySeed());
		xmssPrivateKey.setSecretKeyPRF(privateKey.getSecretKeyPRF());
		xmssPrivateKey.setPublicSeed(privateKey.getPublicSeed());
		xmssPrivateKey.setRoot(new byte[params.getDigestSize()]);

		XMSSPublicKey xmssPublicKey = new XMSSPublicKey(params);
		xmssPublicKey.setPublicSeed(privateKey.getPublicSeed());
		xmssPublicKey.setRoot(new byte[params.getDigestSize()]);
		
		/* import and generate root for top level tree */
		try {
			importKeys(xmssPrivateKey.toByteArray(), xmssPublicKey.toByteArray());
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		/* get root */
		
		/* prepare addresses */
		int layerAddress = params.getLayers() - 1;
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setLayerAddress(layerAddress);
		otsHashAddress.setTreeAddress(0);
		LTreeAddress lTreeAddress = new LTreeAddress();
		lTreeAddress.setLayerAddress(layerAddress);
		lTreeAddress.setTreeAddress(0);
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		hashTreeAddress.setLayerAddress(layerAddress);	
		hashTreeAddress.setTreeAddress(0);
		
		XMSSNode root = treeHash(0, params.getHeight(), otsHashAddress, lTreeAddress, hashTreeAddress);
		setRoot(root.getValue());
		
		/* set XMSS^MT root */
		privateKey.setRoot(getRoot());
		
		/* create XMSS^MT public key */
		publicKey = new XMSSMTPublicKey(this);
		publicKey.setPublicSeed(getPublicSeed());
		publicKey.setRoot(getRoot());
	}
	
	/**
	 * Generate an XMSS^MT private key.
	 * @return XMSS^MT private key.
	 */
	private XMSSMTPrivateKey generatePrivateKey() {
		int n = params.getDigestSize();
		byte[] publicSeed = new byte[n];
		prng.nextBytes(publicSeed);
		byte[] secretKeySeed = new byte[n];
		prng.nextBytes(secretKeySeed);
		byte[] secretKeyPRF = new byte[n];
		prng.nextBytes(secretKeyPRF);
		
		XMSSMTPrivateKey privateKey = new XMSSMTPrivateKey(params);
		privateKey.setPublicSeed(publicSeed);
		privateKey.setSecretKeySeed(secretKeySeed);
		privateKey.setSecretKeyPRF(secretKeyPRF);
		return privateKey;
	}
	
	/**
	 * Import keys.
	 * @param privateKey {@link XMSSMTPrivateKey}.
	 * @param publicKey {@link XMSSMTPublicKey}.
	 */
	/*
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
	*/
	
	/**
	 * Generate an {@link XMSSMTSignature} and update the {@link XMSSMTPrivateKey}
	 * @param message the message to be signed
	 * @return {@link XMSSMTSignature} as byte array
	 */
	@Override
	public byte[] sign(byte[] message) {
		long globalIndex = privateKey.getGlobalIndex();
		if (!XMSSUtil.isIndexValid(params.getTotalHeight(), globalIndex)) {
			throw new IllegalArgumentException("index out of bounds");
		}
		XMSSMTSignature signature = new XMSSMTSignature(params);
		signature.setIndex(globalIndex);

		/* compress message */
		byte[] random =  khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(signature.getIndex(), 32));
		signature.setRandom(random);
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		/* sign compressed message */
		
		/* layer 0 */
		long indexTree = XMSSUtil.getTreeIndex(globalIndex, params.getHeight());
		int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, params.getHeight());
		setIndex(indexLeaf);
		
		/* create signature with XMSS tree on layer 0 */

		/* adjust addresses */
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setLayerAddress(0);
		otsHashAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		wotsPlus.importKeys(getWOTSPlusSecretKey(otsHashAddress), getPublicSeed());
		
		/* sign */
		XMSSSignature tmpSignature = treeSig(messageDigest, otsHashAddress);
		ReducedXMSSSignature reducedSignature = new ReducedXMSSSignature(this);
		reducedSignature.setSignature(tmpSignature.getSignature());
		reducedSignature.setAuthPath(tmpSignature.getAuthPath());
		signature.addReducedSignature(reducedSignature);
		
		/* get root */
		LTreeAddress lTreeAddress = new LTreeAddress();
		lTreeAddress.setLayerAddress(0);
		lTreeAddress.setTreeAddress(indexTree);
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		hashTreeAddress.setLayerAddress(0);
		hashTreeAddress.setTreeAddress(indexTree);
		
		XMSSNode root = treeHash(0, params.getHeight(), otsHashAddress, lTreeAddress, hashTreeAddress);
		/* loop over remaining layers */
		for (int layer = 1; layer < params.getLayers(); layer++) {
			indexLeaf = XMSSUtil.getLeafIndex(indexTree, params.getHeight());
			indexTree = XMSSUtil.getTreeIndex(indexTree, params.getHeight());
			setIndex(indexLeaf);
			
			/* reinitialize WOTS+ object */
			otsHashAddress.setLayerAddress(layer);
			otsHashAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			wotsPlus.importKeys(getWOTSPlusSecretKey(otsHashAddress), getPublicSeed());
			
			/* sign */
			tmpSignature = treeSig(root.getValue(), otsHashAddress);
			reducedSignature = new ReducedXMSSSignature(this);
			reducedSignature.setSignature(tmpSignature.getSignature());
			reducedSignature.setAuthPath(tmpSignature.getAuthPath());
			signature.addReducedSignature(reducedSignature);
			
			/* get root */
			lTreeAddress.setLayerAddress(layer);
			lTreeAddress.setTreeAddress(indexTree);
			hashTreeAddress.setLayerAddress(layer);
			hashTreeAddress.setTreeAddress(indexTree);
			
			root = treeHash(0, params.getHeight(), otsHashAddress, lTreeAddress, hashTreeAddress);
		}
		
		/* update private key */
		privateKey.setGlobalIndex(globalIndex + 1);
		
		return signature.toByteArray();
	}
	
	/**
	 * Verify an {@link XMSSMTSignature} on a message using the {@link XMSSMTPublicKey} of this instance.
	 * @param {@link XMSSMTSignature} signature
	 * @param message
	 * @return true if and only if signature is a valid {@link XMSSMTSignature} on the message under this {@link XMSSMTPublicKey}.  Otherwise, it returns false.
	 * @throws ParseException 
	 */
	@Override
	public boolean verifySignature(byte[] message, byte[] sig, byte[] pubKey) throws ParseException {
		/* (re)create compressed message */
		XMSSMTSignature signature = new XMSSMTSignature(params);
		signature.parseByteArray(sig);
		XMSSMTPublicKey publicKey = new XMSSMTPublicKey(this);
		publicKey.parseByteArray(pubKey);
		
		byte[] concatenated = XMSSUtil.concat(signature.getRandom(), publicKey.getRoot(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);

		long globalIndex = signature.getIndex();
		long indexTree = XMSSUtil.getTreeIndex(globalIndex, params.getHeight());
		int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, params.getHeight());
		setIndex(indexLeaf);

		/* prepare addresses */
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setLayerAddress(0);
		otsHashAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		LTreeAddress lTreeAddress = new LTreeAddress();
		lTreeAddress.setLayerAddress(0);
		lTreeAddress.setTreeAddress(indexTree);
		lTreeAddress.setLTreeAddress(indexLeaf);
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		hashTreeAddress.setLayerAddress(0);
		hashTreeAddress.setTreeAddress(indexTree);
		hashTreeAddress.setTreeIndex(indexLeaf);
		
		/* reinitialize WOTS+ object (only publicSeed needed for verification) */
		wotsPlus.importKeys(new byte[params.getDigestSize()], publicKey.getPublicSeed());

		/* get root node on layer 0 */
		ReducedXMSSSignature xmssMTSignature = signature.getReducedSignature(0);
		XMSSNode rootNode = getRootNodeFromSignature(messageDigest, xmssMTSignature, otsHashAddress, lTreeAddress, hashTreeAddress);
		for (int layer = 1; layer < params.getLayers(); layer++) {
			xmssMTSignature = signature.getReducedSignature(layer);
			indexLeaf = XMSSUtil.getLeafIndex(indexTree, params.getHeight());
			indexTree = XMSSUtil.getTreeIndex(indexTree, params.getHeight());
			setIndex(indexLeaf);
			
			/* adjust addresses */
			otsHashAddress.setLayerAddress(layer);
			otsHashAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			lTreeAddress.setLayerAddress(layer);
			lTreeAddress.setTreeAddress(indexTree);
			lTreeAddress.setLTreeAddress(indexLeaf);
			hashTreeAddress.setLayerAddress(layer);
			hashTreeAddress.setTreeAddress(indexTree);
			hashTreeAddress.setTreeIndex(indexLeaf);
			
			/* get root node */
			rootNode = getRootNodeFromSignature(rootNode.getValue(), xmssMTSignature, otsHashAddress, lTreeAddress, hashTreeAddress);
		}
		
		/* compare roots */
		return XMSSUtil.compareByteArray(rootNode.getValue(), publicKey.getRoot());
	}
	
	public XMSSMTParameters getParams() {
		return params;
	}
	
	public byte[] getPrivateKey() {
		return privateKey.toByteArray();
	}

	public byte[] getPublicKey() {
		return publicKey.toByteArray();
	}
}
