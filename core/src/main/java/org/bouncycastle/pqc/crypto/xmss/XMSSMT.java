package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import java.text.ParseException;

/**
 * XMSS^MT.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMT {
	
	private XMSSMTParameters params;
	private XMSS xmss;
	private SecureRandom prng;
	private KeyedHashFunctions khf;
	private XMSSMTPrivateKey privateKey;
	private XMSSMTPublicKey publicKey;
	

	public XMSSMT(XMSSMTParameters params) {
		super();
		this.params = params;
		xmss = params.getXMSS();
		prng = params.getXMSS().getParams().getPRNG();
		khf = xmss.getKhf();
		privateKey = new XMSSMTPrivateKey(params);
		publicKey = new XMSSMTPublicKey(params);
	}
	
	public void generateKeys() {
		/* generate private key */
		privateKey = generatePrivateKey();
		
		/* init global xmss */
		XMSSPrivateKey xmssPrivateKey = new XMSSPrivateKey(xmss.getParams());
		xmssPrivateKey.setSecretKeySeed(privateKey.getSecretKeySeed());
		xmssPrivateKey.setSecretKeyPRF(privateKey.getSecretKeyPRF());
		xmssPrivateKey.setPublicSeed(privateKey.getPublicSeed());
		xmssPrivateKey.setRoot(new byte[params.getDigestSize()]);

		XMSSPublicKey xmssPublicKey = new XMSSPublicKey(xmss.getParams());
		xmssPublicKey.setPublicSeed(privateKey.getPublicSeed());
		xmssPublicKey.setRoot(new byte[params.getDigestSize()]);
		
		/* import to xmss */
		try {
			xmss.importKeys(xmssPrivateKey.toByteArray(), xmssPublicKey.toByteArray());
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		/* get root */
		
		/* prepare addresses */
		int layerAddress = params.getLayers() - 1;
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setLayerAddress(layerAddress);
		otsHashAddress.setTreeAddress(0);
		
		XMSSNode root = xmss.treeHash(0, xmss.getParams().getHeight(), otsHashAddress);
		xmss.setRoot(root.getValue());
		
		/* set XMSS^MT root */
		privateKey.setRoot(xmss.getRoot());
		
		/* create XMSS^MT public key */
		publicKey = new XMSSMTPublicKey(params);
		publicKey.setPublicSeed(xmss.getPublicSeed());
		publicKey.setRoot(xmss.getRoot());
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
	
	public void importKeys(byte[] privateKey, byte[] publicKey) throws ParseException {
		if (privateKey == null) {
			throw new NullPointerException("privateKey == null");
		}
		if (publicKey == null) {
			throw new NullPointerException("publicKey == null");
		}
		XMSSMTPrivateKey xmssMTPrivateKey = new XMSSMTPrivateKey(params);
		xmssMTPrivateKey.parseByteArray(privateKey);
		XMSSMTPublicKey xmssMTPublicKey = new XMSSMTPublicKey(params);
		xmssMTPublicKey.parseByteArray(publicKey);
		if (!XMSSUtil.compareByteArray(xmssMTPrivateKey.getRoot(), xmssMTPublicKey.getRoot())) {
			throw new IllegalStateException("root of private key and public key do not match");
		}
		if (!XMSSUtil.compareByteArray(xmssMTPrivateKey.getPublicSeed(), xmssMTPublicKey.getPublicSeed())) {
			throw new IllegalStateException("publicSeed of private key and public key do not match");
		}

		/* init global xmss */
		XMSSPrivateKey xmssPrivateKey = new XMSSPrivateKey(xmss.getParams());
		xmssPrivateKey.setSecretKeySeed(xmssMTPrivateKey.getSecretKeySeed());
		xmssPrivateKey.setSecretKeyPRF(xmssMTPrivateKey.getSecretKeyPRF());
		xmssPrivateKey.setPublicSeed(xmssMTPrivateKey.getPublicSeed());
		xmssPrivateKey.setRoot(xmssMTPrivateKey.getRoot());

		XMSSPublicKey xmssPublicKey = new XMSSPublicKey(xmss.getParams());
		xmssPublicKey.setPublicSeed(xmssMTPrivateKey.getPublicSeed());
		xmssPublicKey.setRoot(xmssMTPrivateKey.getRoot());
		
		/* import to xmss */
		try {
			xmss.importKeys(xmssPrivateKey.toByteArray(), xmssPublicKey.toByteArray());
		} catch (ParseException e) {
			e.printStackTrace();
		}
		this.privateKey = xmssMTPrivateKey;
		this.publicKey = xmssMTPublicKey;
	}
	
	public byte[] sign(byte[] message) {
		if (message == null) {
			throw new NullPointerException("message == null");
		}
		/* increase index of private key */
		privateKey.increaseIndex();
		
		long globalIndex = getIndex();
		int totalHeight = params.getHeight();
		int xmssHeight = xmss.getParams().getHeight();
		if (!XMSSUtil.isIndexValid(totalHeight, globalIndex)) {
			throw new IllegalArgumentException("index out of bounds");
		}
		XMSSMTSignature signature = new XMSSMTSignature(params);
		signature.setIndex(globalIndex);

		/* compress message */
		byte[] random =  khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(globalIndex, 32));
		signature.setRandom(random);
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(globalIndex, params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		/* layer 0 */
		long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
		int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);
		
		/* reset xmss */
		xmss.setIndex(indexLeaf);
		xmss.setPublicSeed(getPublicSeed());
		
		/* create signature with XMSS tree on layer 0 */

		/* adjust addresses */
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setLayerAddress(0);
		otsHashAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		
		/* sign message digest */
		XMSSSignature tmpSignature = xmss.treeSig(messageDigest, otsHashAddress);
		XMSSReducedSignature reducedSignature = new XMSSReducedSignature(xmss.getParams());
		reducedSignature.setSignature(tmpSignature.getSignature());
		reducedSignature.setAuthPath(tmpSignature.getAuthPath());
		signature.getReducedSignatures().add(reducedSignature);

		/* loop over remaining layers */
		for (int layer = 1; layer < params.getLayers(); layer++) {
			/* get root of layer - 1*/
			XMSSNode root = xmss.treeHash(0, xmssHeight, otsHashAddress);

			indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
			indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
			xmss.setIndex(indexLeaf);
			
			/* reinitialize WOTS+ object */
			otsHashAddress.setLayerAddress(layer);
			otsHashAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			
			/* sign root digest of layer - 1 */
			tmpSignature = xmss.treeSig(root.getValue(), otsHashAddress);
			reducedSignature = new XMSSReducedSignature(xmss.getParams());
			reducedSignature.setSignature(tmpSignature.getSignature());
			reducedSignature.setAuthPath(tmpSignature.getAuthPath());
			signature.getReducedSignatures().add(reducedSignature);
		}
		
		/* update private key */
		privateKey.setIndex(globalIndex + 1);
		
		return signature.toByteArray();
	}
	
	public boolean verifySignature(byte[] message, byte[] sig, byte[] pubKey) throws ParseException {
		/* (re)create compressed message */
		XMSSMTSignature signature = new XMSSMTSignature(params);
		signature.parseByteArray(sig);
		XMSSMTPublicKey publicKey = new XMSSMTPublicKey(params);
		publicKey.parseByteArray(pubKey);
		
		byte[] concatenated = XMSSUtil.concat(signature.getRandom(), publicKey.getRoot(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);

		long globalIndex = signature.getIndex();
		int xmssHeight = xmss.getParams().getHeight();
		long indexTree = XMSSUtil.getTreeIndex(globalIndex, xmssHeight);
		int indexLeaf = XMSSUtil.getLeafIndex(globalIndex, xmssHeight);
		
		/* adjust xmss */
		xmss.setIndex(indexLeaf);
		xmss.setPublicSeed(publicKey.getPublicSeed());
		
		/* prepare addresses */
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		otsHashAddress.setLayerAddress(0);
		otsHashAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		
		/* get root node on layer 0 */
		XMSSReducedSignature xmssMTSignature = signature.getReducedSignatures().get(0);
		XMSSNode rootNode = xmss.getRootNodeFromSignature(messageDigest, xmssMTSignature, otsHashAddress);
		for (int layer = 1; layer < params.getLayers(); layer++) {
			xmssMTSignature = signature.getReducedSignatures().get(layer);
			indexLeaf = XMSSUtil.getLeafIndex(indexTree, xmssHeight);
			indexTree = XMSSUtil.getTreeIndex(indexTree, xmssHeight);
			xmss.setIndex(indexLeaf);
			
			/* adjust address */
			otsHashAddress.setLayerAddress(layer);
			otsHashAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			
			/* get root node */
			rootNode = xmss.getRootNodeFromSignature(rootNode.getValue(), xmssMTSignature, otsHashAddress);
		}
		
		/* compare roots */
		return XMSSUtil.compareByteArray(rootNode.getValue(), publicKey.getRoot());
	}
	
	public XMSSMTParameters getParams() {
		return params;
	}
	
	public long getIndex() {
		return privateKey.getIndex();
	}

	protected byte[] getPublicSeed() {
		return privateKey.getPublicSeed();
	}
	
	public byte[] getPrivateKey() {
		return privateKey.toByteArray();
	}

	public byte[] getPublicKey() {
		return publicKey.toByteArray();
	}
}
