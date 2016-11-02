package org.bouncycastle.pqc.crypto.xmss;

/**
 * 
 * OTS Hash address.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class OTSHashAddress extends XMSSAddress {
	
	private Integer otsAddress;
	private Integer chainAddress;
	private Integer hashAddress;
	
	public OTSHashAddress() {
		super(XMSSAdressType.OTS);
	}
	
	public OTSHashAddress(Integer layerAddress, Long treeAddress, Integer keyAndMask, Integer otsAddress, Integer chainAddress, Integer hashAddress) {
		super(layerAddress, treeAddress, XMSSAdressType.OTS, keyAndMask);
		this.otsAddress = otsAddress;
		this.chainAddress = chainAddress;
		this.hashAddress = hashAddress;
	}

	@Override
	public byte[] toByteArray() {
		// TODO Auto-generated method stub
		return null;
	}
	
	public Integer getOtsAddress() {
		return otsAddress;
	}

	public void setOtsAddress(Integer otsAddress) {
		this.otsAddress = otsAddress;
	}

	public Integer getChainAddress() {
		return chainAddress;
	}

	public void setChainAddress(Integer chainAddress) {
		this.chainAddress = chainAddress;
	}

	public Integer getHashAddress() {
		return hashAddress;
	}

	public void setHashAddress(Integer hashAddress) {
		this.hashAddress = hashAddress;
	}
}
