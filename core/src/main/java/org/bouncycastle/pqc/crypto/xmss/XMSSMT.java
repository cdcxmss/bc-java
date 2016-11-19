package org.bouncycastle.pqc.crypto.xmss;

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
	

	private XMSSMTParameters params;
	
	private XMSSMTPrivateKey privateKey;
	
	private XMSSMTPublicKey publicKey;
	
	private byte[] publicSeed;
	

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
	public void genKeyPair(){
		privateKey = new XMSSMTPrivateKey(params);
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		XMSSNode root = treeHash(privateKey.getSecretKeySeed(), 0, params.getHeight(), otsHashAddress, lTreeAddress, hashTreeAddress);
		privateKey.setRoot(root.getValue());
		publicKey = new XMSSMTPublicKey(this, root.getValue());
	}
	
	/**
	 * Generate an XMSS^MT signature and update the XMSS^MT private key
	 * @param message the message to be signed
	 * @param skMt {@link XMSSMTPrivateKey}
	 * @return signature of type {@link XMSSMTSignature}
	 */
	public XMSSMTSignature sign(byte[] message, XMSSMTPrivateKey skMt){
		XMSSMTSignature signature = new XMSSMTSignature(params);
		signature.setIndex(skMt.getIndex());
		// Init addresses
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		otsHashAddress.setLayerAddress(0);
		lTreeAddress.setLayerAddress(0);
		hashTreeAddress.setLayerAddress(0);
		
		//update sk
		skMt.setIndex(skMt.getIndex() + 1);
		
		//message compression
		byte[] random =  khf.PRF(skMt.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		byte[] concatenated = XMSSUtil.concat(random, skMt.getRoot(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		//Sign
		int indexTree = skMt.getIndex() >> params.getHeight();//(params.getTotalHeight() - params.getHeight());
		int indexLeaf = skMt.getIndex() & ((1 << params.getHeight()) - 1);//params.getHeight();
		System.out.println("indexTree:\t" + indexTree);
		System.out.println("indexLeaf:\t" + indexLeaf);
		otsHashAddress.setTreeAddress(indexTree);
		lTreeAddress.setTreeAddress(indexTree);
		hashTreeAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		byte[] secretSeed = getSeed(skMt.getSecretKeySeed(), otsHashAddress);
		publicSeed = new byte[params.getDigestSize()]; // need to set publicSeed 
		prng.nextBytes(publicSeed);
		wotsPlus.importKeys(secretSeed, publicSeed);
//		WOTSPlusSignature wotsPlusSig = wotsPlus.sign(messageDigest, otsHashAddress);// instead of calling treeSig we call wotPlusSign and buildAuthPath
//		List<XMSSNode> authPath = buildAuthPath(otsHashAddress);
		XMSSSignature sigTmp = treeSig(0, messageDigest, secretSeed, otsHashAddress);
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
			secretSeed = getSeed(skMt.getSecretKeySeed(), otsHashAddress);
			publicSeed = new byte[params.getDigestSize()]; // need to set publicSeed 
			prng.nextBytes(publicSeed);
			wotsPlus.importKeys(secretSeed, publicSeed);
			sigTmp = treeSig(j, root.getValue(), secretSeed, otsHashAddress);
			signature.addReducedSignature(sigTmp);
		}
		
		return signature;
	}
	
	public boolean verify(XMSSMTSignature sig, byte[] message, XMSSMTPublicKey pk) {
		// Init addresses
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		otsHashAddress.setLayerAddress(0);
		lTreeAddress.setLayerAddress(0);
		hashTreeAddress.setLayerAddress(0);
		
		byte[] concatenated = XMSSUtil.concat(sig.getRandomness(), pk.getRoot(), XMSSUtil.toBytesBigEndian(sig.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		
		int indexTree = sig.getIndex() >> params.getHeight();//(params.getTotalHeight() - params.getHeight());
		int indexLeaf = sig.getIndex() & ((1 << params.getHeight()) - 1);//params.getHeight();
		System.out.println("indexTree:\t" + indexTree);
		System.out.println("indexLeaf:\t" + indexLeaf);
		otsHashAddress.setTreeAddress(indexTree);
		lTreeAddress.setTreeAddress(indexTree);
		hashTreeAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
		XMSSSignature xmssSig = sig.getReducedSignature(0);
		XMSSNode node = getRootNodeFromSignature(indexLeaf, messageDigest, xmssSig, pk.getPublicSeed(), otsHashAddress, lTreeAddress, hashTreeAddress);// index sig.getIndex or as parameter, if parameter indexTree, indexLeaf or 0 j respectively
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
			node = getRootNodeFromSignature(indexLeaf, messageDigest, xmssSig, pk.getPublicSeed(), otsHashAddress, lTreeAddress, hashTreeAddress);
			System.out.println("node:\t" + Arrays.toString(node.getValue()));
		}
		System.out.println("sig root:\t" + Arrays.toString(sig.getReducedSignature(0).getAuthPath().get(0).getValue()));
		System.out.println("node root:\t" + Arrays.toString(node.getValue()));
		System.out.println("pk root:\t" + Arrays.toString(pk.getRoot()));
		if (node.getValue().equals(pk.getRoot())) {
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
