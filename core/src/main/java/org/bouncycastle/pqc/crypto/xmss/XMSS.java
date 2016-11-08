package org.bouncycastle.pqc.crypto.xmss;

/**
 * XMSS.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSS {

	private XMSSParameters params;
	private XMSSPrivateKey privateKey;
	private XMSSPublicKey publicKey;
	
	public XMSS(XMSSParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		this.params = params;
	}
	
	public void genKeyPair() {
		
	}
	
	private XMSSNode lTree(byte[][] wotsPlusPublicKey, LTreeAddress address, byte[] publicSeed) {
		return null;
	}
	
	private XMSSNode treeHash() {
		return null;
	}
	
	public XMSSParameters getParams() {
		return params;
	}
}
