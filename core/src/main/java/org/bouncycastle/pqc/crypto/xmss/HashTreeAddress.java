package org.bouncycastle.pqc.crypto.xmss;

/**
 * 
 * XMSS Hash Tree address.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class HashTreeAddress extends XMSSAddress {
	
	private int padding;
	private int treeHeight;
	private int treeIndex;
	
	public HashTreeAddress() {
		super(0x02);
		padding = 0;
	}

	@Override
	protected void parseByteArraySpecific(byte[] address) {
		padding = XMSSUtil.bytesToIntBigEndian(address, 16);
		treeHeight = XMSSUtil.bytesToIntBigEndian(address, 20);
		treeIndex = XMSSUtil.bytesToIntBigEndian(address, 24);
	}
	
	@Override
	protected void toByteArraySpecific(byte[] out) {
		XMSSUtil.intToBytesBigEndianOffset(out, padding, 16);
		XMSSUtil.intToBytesBigEndianOffset(out, treeHeight, 20);
		XMSSUtil.intToBytesBigEndianOffset(out, treeIndex, 24);
	}
	
	public int getPadding() {
		return padding;
	}
	
	public int getTreeHeight() {
		return treeHeight;
	}

	public void setTreeHeight(int treeHeight) {
		this.treeHeight = treeHeight;
	}

	public int getTreeIndex() {
		return treeIndex;
	}

	public void setTreeIndex(int treeIndex) {
		this.treeIndex = treeIndex;
	}
}
