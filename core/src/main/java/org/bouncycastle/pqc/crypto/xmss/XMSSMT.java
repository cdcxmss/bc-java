package org.bouncycastle.pqc.crypto.xmss;

/**
 * Multi-Tree XMSS 
 * As described in https://tools.ietf.org/html/draft-irtf-cfrg-xmss-hash-based-signatures-07#section-4.2
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 *
 */
public class XMSSMT {
	

	private XMSSMTParameters params;
	
	private XMSSMTPrivateKey privateKey;
	
	private XMSSMTPublicKey publicKey;
	
	private byte[] publicSeed;

	public XMSSMT(XMSSMTParameters params) {
		super();
		this.params = params;
		publicSeed = new byte[params.getDigestSize()];
		params.getPRNG().nextBytes(publicSeed);
	}
	
	/**
	 * Calculates an XMSS^MT private key and an XMSS^MT public key.
	 */
	public void genKeyPair(){
		privateKey = new XMSSMTPrivateKey(params);
		XMSSParameters xmssParams = new XMSSParameters(params.getHeight(), params.getDigest(), params.getPRNG());
		XMSS xmss = new XMSS(xmssParams);
		OTSHashAddress otsHashAddress = new OTSHashAddress();
		LTreeAddress lTreeAddress = new LTreeAddress();
		HashTreeAddress hashTreeAddress = new HashTreeAddress();
		XMSSNode root = xmss.treeHash(privateKey.getSecretKeySeed(), 0, params.getHeight(), otsHashAddress, lTreeAddress, hashTreeAddress);
		privateKey.setRoot(root.getValue());
		publicKey = new XMSSMTPublicKey(xmss, root.getValue());
	}

	public XMSSMTParameters getParams() {
		return params;
	}

	public XMSSMTPrivateKey getPrivateKey() {
		return privateKey;
	}

	public XMSSMTPublicKey getPublicKey() {
		return publicKey;
	}
	
}
