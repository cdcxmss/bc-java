package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

public class XMSSMTSignature implements XMSSStoreableObject {
	
	/**
	 * 
	 */
	private int index;
	
	/**
	 * 
	 */
	private byte[] randomness;
	
	/**
	 * 
	 */
	private List<XMSSSignature> reducedSignatures;
	
	/**
	 * 
	 */
	private XMSSMTParameters params;
	
	/**
	 * 
	 */
	public XMSSMTSignature(XMSSMTParameters params) {
		reducedSignatures = new ArrayList<XMSSSignature>();
		this.params = params;
	}

	public int getIndex() {
		return index;
	}

	public void setIndex(int index) {
		this.index = index;
	}

	public byte[] getRandomness() {
		return randomness;
	}

	public void setRandomness(byte[] randomness) {
		this.randomness = randomness;
	}

	public List<XMSSSignature> getReducedSignatures() {
		return reducedSignatures;
	}

	public void setReducedSignatures(List<XMSSSignature> reducedSignatures) {
		this.reducedSignatures = reducedSignatures;
	}
	
	/**
	 * 
	 * @param sig
	 */
	public void addReducedSignature(XMSSSignature sig) {
		reducedSignatures.add(sig);
	}
	
	/**
	 * 
	 * @param index
	 * @return
	 */
	public XMSSSignature getReducedSignature(int index) {
		return reducedSignatures.get(index);
	}

	@Override
	public byte[] toByteArray() {
		/* index || random || reduced signatures */
		int n = params.getDigestSize();
		int indexSize = (int) Math.ceil(params.getTotalHeight() / (double) 8);
		int randomSize = n;
		int reducedSignaturesSize = (params.getTotalHeight() + params.getWOTSPlus().getParams().getLen() * params.getLayers())* n;
		int totalSize = indexSize + randomSize + reducedSignaturesSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy index */
		XMSSUtil.intToBytesBigEndianOffset(out, index, position);
		position += indexSize;
		/* copy random */
		XMSSUtil.copyBytesAtOffset(out, randomness, position);
		position += randomSize;
		/* copy reduced signatures */
		for(XMSSSignature reducedSig : reducedSignatures) {
			byte[] signature = reducedSig.toByteArray();
			XMSSUtil.copyBytesAtOffset(out, signature, position);
			position += n;//not sure about this
		}
		return out;
	}

	@Override
	public void parseByteArray(byte[] in) throws ParseException {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		int n = params.getDigestSize();
		int len = params.getWOTSPlus().getParams().getLen();
		int height = params.getHeight();// height or TotalHeight?
		int indexSize = (int) Math.ceil(params.getTotalHeight() / (double) 8);
		int randomSize = n;
		int reducedSignaturesSize = (params.getTotalHeight() + len * params.getLayers())* n;
		int totalSize = indexSize + randomSize + reducedSignaturesSize;
		if (in.length != totalSize) {
			throw new ParseException("signature has wrong size", 0);
		}
		int position = 0;
		index = XMSSUtil.bytesToIntBigEndian(in, position);
		if (!XMSSUtil.isIndexValid(height, index)) {
			throw new ParseException("index out of bounds", 0);
		}
		position += indexSize;
		randomness = XMSSUtil.extractBytesAtOffset(in, position, randomSize);
		position += randomSize;
		reducedSignatures = new ArrayList<XMSSSignature>();
		int xmssSigSize = params.getHeight() + len;
		XMSSParameters xmssParameters = new XMSSParameters(params.getHeight(), params.getDigest(), params.getPRNG());
		XMSS xmss = new XMSS(xmssParameters);
		XMSSSignature xmssSig = new XMSSSignature(xmss);
		for (int i = 0; i < reducedSignatures.size(); i++) {
			xmssSig.parseByteArray(XMSSUtil.extractBytesAtOffset(in, position, xmssSigSize));
			reducedSignatures.add(xmssSig);
		}
	}
	
	
}
