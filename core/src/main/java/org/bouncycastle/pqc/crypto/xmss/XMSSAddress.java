package org.bouncycastle.pqc.crypto.xmss;

/**
 * 
 * XMSS Address.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public abstract class XMSSAddress {

	private int layerAddress;
	private long treeAddress;
	private int type;
	private int keyAndMask;
	
	public XMSSAddress(int type) {
		this.type = type;
	}
	
	protected abstract void parseByteArraySpecific(byte[] address);
	protected abstract void toByteArraySpecific(byte[] out);
	
	public final void parseByteArray(byte[] address) {
		if (address.length != 32) {
			throw new IllegalArgumentException("address needs to be 32 byte");
		}
		layerAddress = XMSSUtil.bytesToIntBigEndian(address, 0);
		treeAddress = XMSSUtil.bytesToLongBigEndian(address, 4);
		type = XMSSUtil.bytesToIntBigEndian(address, 12);
		parseByteArraySpecific(address);
		keyAndMask = XMSSUtil.bytesToIntBigEndian(address, 28);
	}

	public final byte[] toByteArray() {
		byte[] out = new byte[32];
		XMSSUtil.intToBytesBigEndianOffset(out, layerAddress, 0);
		XMSSUtil.longToBytesBigEndianOffset(out, treeAddress, 4);
		XMSSUtil.intToBytesBigEndianOffset(out, type, 12);
		toByteArraySpecific(out);
		XMSSUtil.intToBytesBigEndianOffset(out, keyAndMask, 28);
		return out;
	}
	
	public int getLayerAddress() {
		return layerAddress;
	}

	public void setLayerAddress(int layerAddress) {
		this.layerAddress = layerAddress;
	}

	public long getTreeAddress() {
		return treeAddress;
	}

	public void setTreeAddress(long treeAddress) {
		this.treeAddress = treeAddress;
	}

	public int getType() {
		return type;
	}

	public int getKeyAndMask() {
		return keyAndMask;
	}

	public void setKeyAndMask(int keyAndMask) {
		this.keyAndMask = keyAndMask;
	}
}
