package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * XMSSMT Signature.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMTSignature implements XMSSStoreableObject {
	
	private XMSSMTParameters params;
	private long index;
	private byte[] random;
	private List<ReducedXMSSSignature> reducedSignatures;
	
	public XMSSMTSignature(XMSSMTParameters params) {
		super();
		if (params == null) {
			throw new NullPointerException("params == null");
		}
		reducedSignatures = new ArrayList<ReducedXMSSSignature>();
		this.params = params;
	}

	@Override
	public byte[] toByteArray() {
		/* index || random || reduced signatures */
		int n = params.getDigestSize();
		int len = params.getWOTSPlus().getParams().getLen();
		int indexSize = (int)Math.ceil(params.getTotalHeight() / (double) 8);
		int randomSize = n;
		int reducedSignaturesSize = ((params.getHeight() + len) * n) * params.getLayers();
		int totalSize = indexSize + randomSize + reducedSignaturesSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy index */
		byte[] indexBytes = XMSSUtil.toBytesBigEndian(index, indexSize);
		XMSSUtil.copyBytesAtOffset(out, indexBytes, 0);
		position += indexSize;
		/* copy random */
		XMSSUtil.copyBytesAtOffset(out, random, position);
		position += randomSize;
		/* copy reduced signatures */
		int reducedXMSSSignatureSize = (params.getHeight() + len) * n;
		for(ReducedXMSSSignature reducedSignature : reducedSignatures) {
			byte[] signature = reducedSignature.toByteArray();
			XMSSUtil.copyBytesAtOffset(out, signature, position);
			position += reducedXMSSSignatureSize;
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
		int totalHeight = params.getTotalHeight();
		int indexSize = (int) Math.ceil(params.getTotalHeight() / (double) 8);
		int randomSize = n;
		int reducedSignaturesSize = (params.getTotalHeight() + len * params.getLayers())* n;
		int totalSize = indexSize + randomSize + reducedSignaturesSize;
		if (in.length != totalSize) {
			throw new ParseException("signature has wrong size", 0);
		}
		int position = 0;
		index = XMSSUtil.bytesToXBigEndian(in, position, indexSize);
		if (!XMSSUtil.isIndexValid(totalHeight, index)) {
			throw new ParseException("index out of bounds", 0);
		}
		position += indexSize;
		random = XMSSUtil.extractBytesAtOffset(in, position, randomSize);
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

	public long getIndex() {
		return index;
	}

	public void setIndex(long index) {
		this.index = index;
	}

	public byte[] getRandom() {
		return random;
	}

	public void setRandom(byte[] randomness) {
		this.random = randomness;
	}

	public List<ReducedXMSSSignature> getReducedSignatures() {
		return reducedSignatures;
	}

	public void setReducedSignatures(List<ReducedXMSSSignature> reducedSignatures) {
		this.reducedSignatures = reducedSignatures;
	}
	
	public void addReducedSignature(ReducedXMSSSignature sig) {
		reducedSignatures.add(sig);
	}
	
	public ReducedXMSSSignature getReducedSignature(int index) {
		return reducedSignatures.get(index);
	}
}
