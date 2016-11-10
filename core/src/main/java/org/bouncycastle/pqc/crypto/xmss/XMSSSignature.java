package org.bouncycastle.pqc.crypto.xmss;

import java.util.List;

/**
 * XMSS Signature.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSSignature {

	private int index;
	private byte[] random;
	private WOTSPlusSignature signature;
	private List<XMSSNode> authPath;
	
	public XMSSSignature(WOTSPlusSignature signature, List<XMSSNode> authPath) {
		super();
		if (signature == null) {
			throw new NullPointerException("signature == null");
		}
		if (authPath == null) {
			throw new NullPointerException("authPath == null");
		}
		this.signature = signature;
		this.authPath = authPath;
	}

	public byte[] toByteArray() {
		/* TODO */
		return null;
	}

	public int getIndex() {
		return index;
	}

	public void setIndex(int index) {
		this.index = index;
	}

	public byte[] getRandom() {
		return XMSSUtil.byteArrayDeepCopy(random);
	}

	public void setRandom(byte[] random) {
		this.random = random;
	}

	public WOTSPlusSignature getSignature() {
		return signature;
	}

	public List<XMSSNode> getAuthPath() {
		return authPath;
	}
}
