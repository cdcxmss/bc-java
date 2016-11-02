package org.bouncycastle.pqc.crypto.xmss;

/**
 * 
 * XMSS Hash Tree address.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class HashTreeAddress extends XMSSAddress {
	
	private Integer padding;
	private Integer treeHeight;
	private Integer treeIndex;
	
	public HashTreeAddress() {
		super(XMSSAdressType.HashTree);
	}
	public HashTreeAddress(Integer layerAddress, Long treeAddress, Integer keyAndMask, Integer padding, Integer treeHeight, Integer treeIndex) {
		super(layerAddress, treeAddress, XMSSAdressType.HashTree, keyAndMask);
		this.padding = padding;
		this.treeHeight = treeHeight;
		this.treeIndex = treeIndex;
	}

	@Override
	public byte[] toByteArray() {
		// TODO Auto-generated method stub
		return null;
	}
	
	public Integer getPadding() {
		return padding;
	}

	public void setPadding(Integer padding) {
		this.padding = padding;
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
