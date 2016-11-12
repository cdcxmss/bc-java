package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * XMSS Signature.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSSignature implements XMSSStoreableObject {

	/**
	 * XMSS object.
	 */
	private XMSS xmss;
	/**
	 * Index of signature.
	 */
	private int index;
	/**
	 * Random used to create digest of message.
	 */
	private byte[] random;
	/**
	 * WOTS+ signature.
	 */
	private WOTSPlusSignature signature;
	/**
	 * Authentication path.
	 */
	private List<XMSSNode> authPath;
	
	/**
	 * Constructor...
	 * @param signature The WOTS+ signature.
	 * @param authPath The authentication path.
	 */
	public XMSSSignature(XMSS xmss) {
		super();
		if (xmss == null) {
			throw new NullPointerException("xmss == null");
		}
		this.xmss = xmss;
	}

	@Override
	public byte[] toByteArray() {
		/* index || random || signature || authentication path */
		int n = xmss.getParams().getDigestSize();
		int indexSize = 4;
		int randomSize = n;
		int signatureSize = xmss.getWOTSPlus().getParams().getLen() * n;
		int authPathSize = xmss.getParams().getHeight() * n;
		int totalSize = indexSize + randomSize + signatureSize + authPathSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy index */
		XMSSUtil.intToBytesBigEndianOffset(out, index, position);
		position += indexSize;
		/* copy random */
		XMSSUtil.copyBytesAtOffset(out, random, position);
		position += randomSize;
		/* copy signature */
		byte[][] signature = this.signature.toByteArray();
		for (int i = 0; i < signature.length; i++) {
			XMSSUtil.copyBytesAtOffset(out, signature[i], position);
			position += n;
		}
		/* copy authentication path */
		for (int i = 0; i < authPath.size(); i++) {
			byte[] value = authPath.get(i).getValue();
			XMSSUtil.copyBytesAtOffset(out, value, position);
			position += n;
		}
		return out;
	}

	@Override
	public void parseByteArray(byte[] in) throws ParseException {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		int n = xmss.getParams().getDigestSize();
		int len = xmss.getWOTSPlus().getParams().getLen();
		int height = xmss.getParams().getHeight();
		int indexSize = 4;
		int randomSize = n;
		int signatureSize = len * n;
		int authPathSize = height * n;
		int totalSize = indexSize + randomSize + signatureSize + authPathSize;
		if (in.length != totalSize) {
			throw new IllegalArgumentException("wrong size");
		}
		int position = 0;
		index = XMSSUtil.bytesToIntBigEndian(in, position);
		position += indexSize;
		random = XMSSUtil.extractBytesAtOffset(in, position, randomSize);
		position += randomSize;
		byte[][] wotsPlusSignature = new byte[xmss.getWOTSPlus().getParams().getLen()][];
		for (int i = 0; i < wotsPlusSignature.length; i++) {
			wotsPlusSignature[i] = XMSSUtil.extractBytesAtOffset(in, position, n);
			position += n;
		}
		signature = new WOTSPlusSignature(xmss.getWOTSPlus().getParams(), wotsPlusSignature);
		List<XMSSNode> nodeList = new ArrayList<XMSSNode>();
		for (int i = 0; i < height; i++) {
			nodeList.add(new XMSSNode(i, XMSSUtil.extractBytesAtOffset(in, position, n)));
			position += n;
		}
		authPath = nodeList;
	}

	/**
	 * Getter index.
	 * @return index.
	 */
	public int getIndex() {
		return index;
	}

	/**
	 * Setter index.
	 * @param index
	 */
	public void setIndex(int index) {
		this.index = index;
	}

	/**
	 * Getter random.
	 * @return random.
	 */
	public byte[] getRandom() {
		return XMSSUtil.cloneArray(random);
	}

	/**
	 * Setter random.
	 * @param random random.
	 */
	public void setRandom(byte[] random) {
		this.random = random;
	}

	/**
	 * Getter signature.
	 * @return WOTS+ signature.
	 */
	public WOTSPlusSignature getSignature() {
		return signature;
	}
	
	/**
	 * Setter WOTS+ signature
	 * @param signature WOTS+ signature.
	 */
	public void setSignature(WOTSPlusSignature signature) {
		this.signature = signature;
	}

	/**
	 * Getter authentication path.
	 * @return Authentication path.
	 */
	public List<XMSSNode> getAuthPath() {
		return authPath;
	}
	
	/**
	 * Setter authentication path.
	 * @param authPath Authentication path.
	 */
	public void setAuthPath(List<XMSSNode> authPath) {
		this.authPath = authPath;
	}
}
