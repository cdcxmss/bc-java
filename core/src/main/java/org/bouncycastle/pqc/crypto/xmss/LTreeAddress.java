package org.bouncycastle.pqc.crypto.xmss;

/**
 * 
 * XMSS L-tree address.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class LTreeAddress extends XMSSAddress {
	
	private Integer lTreeAddress;
	private Integer treeHeight;
	private Integer treeIndex;
	
	public LTreeAddress() {
		super(XMSSAdressType.LTree);
	}
	
	public LTreeAddress(Integer layerAddress, Long treeAddress, Integer keyAndMask, Integer lTreeAddress, Integer treeHeight, Integer treeIndex) {
		super(layerAddress, treeAddress, XMSSAdressType.LTree, keyAndMask);
		this.lTreeAddress = lTreeAddress;
		this.treeHeight = treeHeight;
		this.treeIndex = treeIndex;
	}

	@Override
	public byte[] toByteArray() {
		// TODO Auto-generated method stub
		return null;
	}
	
	public Integer getlTreeAddress() {
		return lTreeAddress;
	}

	public void setlTreeAddress(Integer lTreeAddress) {
		this.lTreeAddress = lTreeAddress;
	}

	public Integer getTreeHeight() {
		return treeHeight;
	}

	public void setTreeHeight(Integer treeHeight) {
		this.treeHeight = treeHeight;
	}

	public Integer getTreeIndex() {
		return treeIndex;
	}

	public void setTreeIndex(Integer treeIndex) {
		this.treeIndex = treeIndex;
	}
}
