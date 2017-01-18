package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * XMSS^MT.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMT extends XMSS {
	
	private XMSSMTParameters params;
	private XMSSMTPrivateKey privateKey;
	private XMSSMTPublicKey publicKey;
	

	public XMSSMT(XMSSMTParameters params) {
		super(params);
		this.params = params;
	}
	
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
		
		XMSSNode root = treeHash(0, params.getHeight(), otsHashAddress);
		setRoot(root.getValue());
		
		/* set XMSS^MT root */
		privateKey.setRoot(getRoot());
		
		/* create XMSS^MT public key */
		publicKey = new XMSSMTPublicKey(params);
		publicKey.setPublicSeed(getPublicSeed());
		publicKey.setRoot(getRoot());
	}
	
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
	
	@Override
	public byte[] sign(byte[] message) {
		long globalIndex = privateKey.getGlobalIndex();
		if (!XMSSUtil.isIndexValid(params.getTotalHeight(), globalIndex)) {
			throw new IllegalArgumentException("index out of bounds");
		}
		XMSSMTSignature signature = new XMSSMTSignature(params);
		signature.setIndex(globalIndex);

		/* compress message */
		byte[] random =  khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(globalIndex, 32));
		signature.setRandom(random);
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(globalIndex, params.getDigestSize()));
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
		
		/* sign message digest */
		XMSSSignature tmpSignature = treeSig(messageDigest, otsHashAddress);
		XMSSReducedSignature reducedSignature = new XMSSReducedSignature(params);
		reducedSignature.setSignature(tmpSignature.getSignature());
		reducedSignature.setAuthPath(tmpSignature.getAuthPath());
		signature.getReducedSignatures().add(reducedSignature);

		/* loop over remaining layers */
		for (int layer = 1; layer < params.getLayers(); layer++) {
			/* get root of layer - 1*/
			XMSSNode root = treeHash(0, params.getHeight(), otsHashAddress);

			indexLeaf = XMSSUtil.getLeafIndex(indexTree, params.getHeight());
			indexTree = XMSSUtil.getTreeIndex(indexTree, params.getHeight());
			setIndex(indexLeaf);
			
			/* reinitialize WOTS+ object */
			otsHashAddress.setLayerAddress(layer);
			otsHashAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			wotsPlus.importKeys(getWOTSPlusSecretKey(otsHashAddress), getPublicSeed());
			
			/* sign root digest of layer - 1 */
			tmpSignature = treeSig(root.getValue(), otsHashAddress);
			reducedSignature = new XMSSReducedSignature(params);
			reducedSignature.setSignature(tmpSignature.getSignature());
			reducedSignature.setAuthPath(tmpSignature.getAuthPath());
			signature.getReducedSignatures().add(reducedSignature);
		}
		
		/* update private key */
		privateKey.setGlobalIndex(globalIndex + 1);
		
		return signature.toByteArray();
	}
	
	@Override
	public boolean verifySignature(byte[] message, byte[] sig, byte[] pubKey) throws ParseException {
		/* (re)create compressed message */
		XMSSMTSignature signature = new XMSSMTSignature(params);
		signature.parseByteArray(sig);
		XMSSMTPublicKey publicKey = new XMSSMTPublicKey(params);
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
		
		/* reinitialize WOTS+ object (only publicSeed needed for verification) */
		wotsPlus.importKeys(new byte[params.getDigestSize()], publicKey.getPublicSeed());

		/* get root node on layer 0 */
		XMSSReducedSignature xmssMTSignature = signature.getReducedSignatures().get(0);
		XMSSNode rootNode = getRootNodeFromSignature(messageDigest, xmssMTSignature, otsHashAddress);
		for (int layer = 1; layer < params.getLayers(); layer++) {
			xmssMTSignature = signature.getReducedSignatures().get(layer);
			indexLeaf = XMSSUtil.getLeafIndex(indexTree, params.getHeight());
			indexTree = XMSSUtil.getTreeIndex(indexTree, params.getHeight());
			setIndex(indexLeaf);
			
			/* adjust address */
			otsHashAddress.setLayerAddress(layer);
			otsHashAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			
			/* get root node */
			rootNode = getRootNodeFromSignature(rootNode.getValue(), xmssMTSignature, otsHashAddress);
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
