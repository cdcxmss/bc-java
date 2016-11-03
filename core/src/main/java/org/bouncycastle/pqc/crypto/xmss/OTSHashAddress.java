package org.bouncycastle.pqc.crypto.xmss;

/**
 * 
 * OTS Hash address.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class OTSHashAddress extends XMSSAddress {
	
	private int otsAddress;
	private int chainAddress;
	private int hashAddress;
	
	public OTSHashAddress() {
		super(0x00);
	}
	
	@Override
	protected void parseByteArraySpecific(byte[] address) {
		otsAddress = XMSSUtil.bytesToIntBigEndian(address, 16);
		chainAddress = XMSSUtil.bytesToIntBigEndian(address, 20);
		hashAddress = XMSSUtil.bytesToIntBigEndian(address, 24);
	}
	
	@Override
	protected void toByteArraySpecific(byte[] out) {
		XMSSUtil.intToBytesBigEndianOffset(out, otsAddress, 16);
		XMSSUtil.intToBytesBigEndianOffset(out, chainAddress, 20);
		XMSSUtil.intToBytesBigEndianOffset(out, hashAddress, 24);
	}
	
	public int getOTSAddress() {
		return otsAddress;
	}

	public void setOTSAddress(int otsAddress) {
		this.otsAddress = otsAddress;
	}

	public int getChainAddress() {
		return chainAddress;
	}

	public void setChainAddress(int chainAddress) {
		this.chainAddress = chainAddress;
	}

	public int getHashAddress() {
		return hashAddress;
	}

	public void setHashAddress(int hashAddress) {
		this.hashAddress = hashAddress;
	}
}
