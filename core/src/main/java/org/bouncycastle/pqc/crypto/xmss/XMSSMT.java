package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

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
	 * 
	 */
	private XMSSMTParameters params;
	
	/**
	 * 
	 */
	private XMSSMTPrivateKey privateKey;
	
	/**
	 * 
	 */
	private XMSSMTPublicKey publicKey;
	

	public XMSSMT(XMSSMTParameters params) {
		super(new XMSSParameters(params.getHeight(), params.getDigest(), params.getPRNG()));
		this.params = params;
		publicSeed = new byte[params.getDigestSize()];
		params.getPRNG().nextBytes(publicSeed);
		khf = new KeyedHashFunctions(params.getDigest(), params.getDigestSize());
	}
	
	/**
	 * Calculates an XMSS^MT private key and an XMSS^MT public key.
	 */
	@Override
	public void generateKeys(){
		privateKey = new XMSSMTPrivateKey(params);
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		XMSSNode root = treeHash(privateKey.getSecretKeySeed(), 0, params.getHeight(), otsHashAddress, lTreeAddress, hashTreeAddress);
		privateKey.setRoot(root.getValue());
		publicKey = new XMSSMTPublicKey(this);
		publicKey.setRoot(root.getValue());
	}
	
	/**
	 * 
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
		this.publicSeed = this.privateKey.getPublicSeed();
	}
	
	/**
	 * Generate an XMSS^MT signature and update the XMSS^MT private key
	 * @param message the message to be signed
	 * @return {@link XMSSMTSignature} as byte array
	 */
	@Override
	public byte[] sign(byte[] message){
		XMSSMTSignature signature = new XMSSMTSignature(params);
		signature.setIndex(privateKey.getIndex());
		// Init addresses
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		otsHashAddress.setLayerAddress(0);
		lTreeAddress.setLayerAddress(0);
		hashTreeAddress.setLayerAddress(0);
		
		//update sk
		privateKey.setIndex(privateKey.getIndex() + 1);
		
		//message compression
		byte[] random =  khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		//Sign
		int indexTree = privateKey.getIndex() >> params.getHeight();//(params.getTotalHeight() - params.getHeight());
		int indexLeaf = privateKey.getIndex() & ((1 << params.getHeight()) - 1);//params.getHeight();
		System.out.println("indexTree:\t" + indexTree);
		System.out.println("indexLeaf:\t" + indexLeaf);
		otsHashAddress.setTreeAddress(indexTree);
		lTreeAddress.setTreeAddress(indexTree);
		hashTreeAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		byte[] secretSeed = getSeed(privateKey.getSecretKeySeed(), otsHashAddress);
		publicSeed = new byte[params.getDigestSize()]; // need to set publicSeed 
		prng.nextBytes(publicSeed);
		wotsPlus.importKeys(secretSeed, publicSeed);
//		WOTSPlusSignature wotsPlusSig = wotsPlus.sign(messageDigest, otsHashAddress);// instead of calling treeSig we call wotPlusSign and buildAuthPath
//		List<XMSSNode> authPath = buildAuthPath(otsHashAddress);
		ReducedXMSSSignature sigTmp = treeSig(indexLeaf, messageDigest, secretSeed, otsHashAddress);
		signature.setRandomness(random);
		signature.addReducedSignature(sigTmp);
		
		for (int j = 1; j < params.getLayers(); j++) {
			XMSSNode root = treeHash(secretSeed, 0, params.getHeight(), otsHashAddress, lTreeAddress, hashTreeAddress);
			indexTree = indexTree >> params.getHeight();//(params.getTotalHeight() - params.getHeight());
			indexLeaf = indexTree & ((1 << params.getHeight()) - 1); //params.getHeight();
			System.out.println("indexTree:\t" + indexTree);
			System.out.println("indexLeaf:\t" + indexLeaf);
			otsHashAddress.setLayerAddress(j);
			lTreeAddress.setLayerAddress(j);
			hashTreeAddress.setLayerAddress(j);
			otsHashAddress.setTreeAddress(indexTree);
			lTreeAddress.setTreeAddress(indexTree);
			hashTreeAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			secretSeed = getSeed(privateKey.getSecretKeySeed(), otsHashAddress);
			publicSeed = new byte[params.getDigestSize()]; // need to set publicSeed 
			prng.nextBytes(publicSeed);
			wotsPlus.importKeys(secretSeed, publicSeed);
			sigTmp = treeSig(indexLeaf, root.getValue(), secretSeed, otsHashAddress);
			signature.addReducedSignature(sigTmp);
		}
		
		return signature.toByteArray();
	}
	
	/**
	 * 
	 * @param sig
	 * @param message
	 * @return
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
		byte[] concatenated = XMSSUtil.concat(sig.getRandomness(), publicKey.getRoot(), XMSSUtil.toBytesBigEndian(sig.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		int indexTree = sig.getIndex() >> params.getHeight();//(params.getTotalHeight() - params.getHeight());
		int indexLeaf = sig.getIndex() & ((1 << params.getHeight()) - 1);//params.getHeight();
		System.out.println("indexTree:\t" + indexTree);
		System.out.println("indexLeaf:\t" + indexLeaf);
		otsHashAddress.setTreeAddress(indexTree);
		lTreeAddress.setTreeAddress(indexTree);
		hashTreeAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		ReducedXMSSSignature xmssSig = sig.getReducedSignature(0);
		XMSSNode node = getRootNodeFromSignature(indexLeaf, messageDigest, xmssSig, publicKey.getPublicSeed(), otsHashAddress, lTreeAddress, hashTreeAddress);// index sig.getIndex or as parameter, if parameter indexTree, indexLeaf or 0 j respectively
		System.out.println("node:\t" + Arrays.toString(node.getValue()));
		for (int j = 1; j < params.getLayers(); j++) {
			indexTree = indexTree >> params.getHeight();//(params.getTotalHeight() - params.getHeight());
			indexLeaf = indexTree & ((1 << params.getHeight()) - 1); //params.getHeight();
			System.out.println("indexTree:\t" + indexTree);
			System.out.println("indexLeaf:\t" + indexLeaf);
			xmssSig = sig.getReducedSignature(j);
			otsHashAddress.setLayerAddress(j);
			lTreeAddress.setLayerAddress(j);
			hashTreeAddress.setLayerAddress(j);
			otsHashAddress.setTreeAddress(indexTree);
			lTreeAddress.setTreeAddress(indexTree);
			hashTreeAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			node = getRootNodeFromSignature(indexLeaf, messageDigest, xmssSig, publicKey.getPublicSeed(), otsHashAddress, lTreeAddress, hashTreeAddress);
			System.out.println("node:\t" + Arrays.toString(node.getValue()));
		}
		System.out.println("sig root:\t" + Arrays.toString(sig.getReducedSignature(0).getAuthPath().get(0).getValue()));
		System.out.println("node root:\t" + Arrays.toString(node.getValue()));
		System.out.println("pk root:\t" + Arrays.toString(publicKey.getRoot()));
		if (node.getValue().equals(publicKey.getRoot())) {
			return true;
		}
		return false;
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
