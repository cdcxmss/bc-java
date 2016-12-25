package org.bouncycastle.pqc.crypto.xmss;

/**
 * Node of the binary tree.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
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
		return XMSSUtil.cloneArray(value);
	}
	
	public void setValue(byte[] value) {
		this.value = value;
	}
	
	@Override
    public XMSSNode clone() {
	return new XMSSNode(height, XMSSUtil.cloneArray(value));
    }
}
