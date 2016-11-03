package org.bouncycastle.pqc.crypto.xmss;

/**
 * 
 * XMSS L-tree address.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class LTreeAddress extends XMSSAddress {
	
	private int lTreeAddress;
	private int treeHeight;
	private int treeIndex;
	
	public LTreeAddress() {
		super(0x01);
	}

	@Override
	protected void parseByteArraySpecific(byte[] address) {
		lTreeAddress = XMSSUtil.bytesToIntBigEndian(address, 16);
		treeHeight = XMSSUtil.bytesToIntBigEndian(address, 20);
		treeIndex = XMSSUtil.bytesToIntBigEndian(address, 24);
	}
	
	@Override
	protected void toByteArraySpecific(byte[] out) {
		XMSSUtil.intToBytesBigEndianOffset(out, lTreeAddress, 16);
		XMSSUtil.intToBytesBigEndianOffset(out, treeHeight, 20);
		XMSSUtil.intToBytesBigEndianOffset(out, treeIndex, 24);
	}
	
	public int getLTreeAddress() {
		return lTreeAddress;
	}

	public void setLTreeAddress(int lTreeAddress) {
		this.lTreeAddress = lTreeAddress;
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
