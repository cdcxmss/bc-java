package org.bouncycastle.pqc.crypto.xmss;

/**
 * 
 * XMSS Address.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public abstract class XMSSAddress {

	public enum XMSSAdressType {
		OTS, LTree, HashTree;
	}
	
	private Integer layerAddress;
	private Long treeAddress;
	private XMSSAdressType type;
	private Integer keyAndMask;
	
	public XMSSAddress(XMSSAdressType type) {
		this.type = type;
	}
	
	public XMSSAddress(Integer layerAddress, Long treeAddress, XMSSAdressType type, Integer keyAndMask) {
		super();
		this.layerAddress = layerAddress;
		this.treeAddress = treeAddress;
		this.type = type;
		this.keyAndMask = keyAndMask;
	}

	public abstract byte[] toByteArray();
	
	public Integer getLayerAddress() {
		return layerAddress;
	}

	public void setLayerAddress(Integer layerAddress) {
		this.layerAddress = layerAddress;
	}

	public Long getTreeAddress() {
		return treeAddress;
	}

	public void setTreeAddress(Long treeAddress) {
		this.treeAddress = treeAddress;
	}

	public XMSSAdressType getType() {
		return type;
	}

	public void setType(XMSSAdressType type) {
		this.type = type;
	}

	public Integer getKeyAndMask() {
		return keyAndMask;
	}

	public void setKeyAndMask(Integer keyAndMask) {
		this.keyAndMask = keyAndMask;
	}
}
