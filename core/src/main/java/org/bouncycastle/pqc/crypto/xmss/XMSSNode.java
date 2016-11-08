package org.bouncycastle.pqc.crypto.xmss;

/**
 * Node of the binary tree.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSNode {

	private int height;
	private byte[] value;
	
	public XMSSNode(int height, byte[] value) {
		super();
		this.height = height;
		this.value = value;
	}

	public int getHeight() {
		return height;
	}
	
	public void setHeight(int height) {
		this.height = height;
	}

	public byte[] getValue() {
		return value;
	}
}
