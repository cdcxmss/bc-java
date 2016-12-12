package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

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
		HexBinaryAdapter adapter = new HexBinaryAdapter();
		String rootStringOrig = adapter.marshal(privateKey.getRoot());
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
		privateKey.setIndex(index + 1);//in ref nach update immer noch der selbe idx = 0
		
		//message compression
		
		byte[] random =  khf.PRF(privateKey.getSecretKeyPRF(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		String randomString = adapter.marshal(random);
		String rootString = adapter.marshal(privateKey.getRoot());
		byte[] concatenated = XMSSUtil.concat(random, privateKey.getRoot(), XMSSUtil.toBytesBigEndian(signature.getIndex(), params.getDigestSize()));
		byte[] messageDigest = khf.HMsg(concatenated, message);
		String msgDigestString = adapter.marshal(messageDigest);
		
		//Sign
		int indexTree = index >> params.getHeight();
		int indexLeaf = index & ((1 << params.getHeight()) - 1);
		System.out.println("indexTree:\t" + indexTree);
		System.out.println("indexLeaf:\t" + indexLeaf);
		otsHashAddress.setTreeAddress(indexTree);
		lTreeAddress.setTreeAddress(indexTree);
		hashTreeAddress.setTreeAddress(indexTree);
		otsHashAddress.setOTSAddress(indexLeaf);
//		byte[] secretSeed = getWOTSPlusSecretKey(indexTree, 0, index);
		byte[] secretSeed = getSeed(privateKey.getSecretKeySeed(), otsHashAddress);
		String secretSeedString = adapter.marshal(secretSeed);//different from referenz
		wotsPlus.importKeys(secretSeed, publicSeed);
//		WOTSPlusSignature wotsPlusSig = wotsPlus.sign(messageDigest, otsHashAddress);// instead of calling treeSig we call wotPlusSign and buildAuthPath
//		List<XMSSNode> authPath = buildAuthPath(indexLeaf,otsHashAddress,);
		ReducedXMSSSignature sigTmp = treeSig(indexLeaf, messageDigest, privateKey.getSecretKeySeed(), privateKey.getPublicSeed(), otsHashAddress);//secretSeed
		String xmssSigString = adapter.marshal(sigTmp.toByteArray());
		signature.setRandomness(random);
		signature.addReducedSignature(sigTmp);
		
		for (int j = 1; j < params.getLayers(); j++) {
			XMSSNode root = treeHash(privateKey.getSecretKeySeed(), privateKey.getPublicSeed(), 0, params.getHeight(), otsHashAddress, lTreeAddress, hashTreeAddress);//secretSeed
			indexTree = indexTree >> params.getHeight();
			indexLeaf = indexTree & ((1 << params.getHeight()) - 1);
			System.out.println("indexTree:\t" + indexTree);
			System.out.println("indexLeaf:\t" + indexLeaf);
			otsHashAddress.setLayerAddress(j);
			lTreeAddress.setLayerAddress(j);
			hashTreeAddress.setLayerAddress(j);
			otsHashAddress.setTreeAddress(indexTree);
			lTreeAddress.setTreeAddress(indexTree);
			hashTreeAddress.setTreeAddress(indexTree);
			otsHashAddress.setOTSAddress(indexLeaf);
			secretSeed = getWOTSPlusSecretKey(indexTree, j, index);
			wotsPlus.importKeys(secretSeed, publicSeed);
			sigTmp = treeSig(indexLeaf, root.getValue(), privateKey.getSecretKeySeed(), privateKey.getPublicSeed(), otsHashAddress);//secretSeed
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
