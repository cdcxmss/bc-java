package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * XMSSMT Signature.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSMTSignature implements XMSSStoreableObject {
	
	/**
	 * 
	 */
	private long index;
	
	/**
	 * 
	 */
	private byte[] randomness;
	
	/**
	 * 
	 */
	private List<ReducedXMSSSignature> reducedSignatures;
	
	/**
	 * 
	 */
	private XMSSMTParameters params;
	
	/**
	 * 
	 */
	public XMSSMTSignature(XMSSMTParameters params) {
		reducedSignatures = new ArrayList<ReducedXMSSSignature>();
		this.params = params;
	}

	public long getIndex() {
		return index;
	}

	public void setIndex(long index) {
		this.index = index;
	}

	public byte[] getRandomness() {
		return randomness;
	}

	public void setRandomness(byte[] randomness) {
		this.randomness = randomness;
	}

	public List<ReducedXMSSSignature> getReducedSignatures() {
		return reducedSignatures;
	}

	public void setReducedSignatures(List<ReducedXMSSSignature> reducedSignatures) {
		this.reducedSignatures = reducedSignatures;
	}
	
	/**
	 * 
	 * @param sig
	 */
	public void addReducedSignature(ReducedXMSSSignature sig) {
		reducedSignatures.add(sig);
	}
	
	/**
	 * 
	 * @param index
	 * @return
	 */
	public ReducedXMSSSignature getReducedSignature(int index) {
		return reducedSignatures.get(index);
	}

	@Override
	public byte[] toByteArray() {
		/* index || random || reduced signatures */
		int n = params.getDigestSize();
		int len = params.getWOTSPlus().getParams().getLen();
		int indexSize = (int) Math.ceil(params.getTotalHeight() / (double) 8);
		int randomSize = n;
		int reducedSignaturesSize = (params.getTotalHeight() + len * params.getLayers())* n;
		int totalSize = indexSize + randomSize + reducedSignaturesSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy index */
		byte[] indexBytes = XMSSUtil.toBytesBigEndian(index, indexSize);
		System.arraycopy(indexBytes, 0, out, position, indexSize);
		position += indexSize;
		/* copy random */
		XMSSUtil.copyBytesAtOffset(out, randomness, position);
		position += randomSize;
		/* copy reduced signatures */
		int reducedXmssSigSize = (params.getHeight() + len) * n;
		for(ReducedXMSSSignature reducedSig : reducedSignatures) {
			byte[] signature = reducedSig.toByteArray();
			XMSSUtil.copyBytesAtOffset(out, signature, position);
			position += reducedXmssSigSize;
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
		int height = params.getHeight();
		int indexSize = (int) Math.ceil(params.getTotalHeight() / (double) 8);
		int randomSize = n;
		int reducedSignaturesSize = (params.getTotalHeight() + len * params.getLayers())* n;
		int totalSize = indexSize + randomSize + reducedSignaturesSize;
		if (in.length != totalSize) {
			throw new ParseException("signature has wrong size", 0);
		}
		int position = 0;
		index = (int)XMSSUtil.bytesToXBigEndian(in, position, indexSize);
		if (!XMSSUtil.isIndexValid(height, index)) {
			throw new ParseException("index out of bounds", 0);
		}
		position += indexSize;
		randomness = XMSSUtil.extractBytesAtOffset(in, position, randomSize);
		position += randomSize;
		reducedSignatures = new ArrayList<ReducedXMSSSignature>();
		int reducedXmssSigSize = (params.getHeight() + len) * n;
		XMSSParameters xmssParameters = new XMSSParameters(params.getHeight(), params.getDigest(), params.getPRNG());
		XMSS xmss = new XMSS(xmssParameters);
		while (position < in.length) {
			ReducedXMSSSignature xmssSig = new ReducedXMSSSignature(xmss);
			xmssSig.parseByteArray(XMSSUtil.extractBytesAtOffset(in, position, reducedXmssSigSize));
			reducedSignatures.add(xmssSig);
			position += reducedXmssSigSize;
		}
	}
	
	
}
