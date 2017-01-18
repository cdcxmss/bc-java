package org.bouncycastle.pqc.crypto.xmss;

import java.text.ParseException;

/**
 * XMSSMT Private Key.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSMTPrivateKey implements XMSSStoreableObjectInterface {
	
	private XMSSMTParameters params;
	private long globalIndex;
	private byte[] secretKeySeed;
	private byte[] secretKeyPRF;
	private byte[] publicSeed;
	private byte[] root;
	
	public XMSSMTPrivateKey(XMSSMTParameters params) {
		super();
		this.params = params;
		globalIndex = 0;
	}
	
	@Override
	public byte[] toByteArray() {
		/* index || secretKeySeed || secretKeyPRF || publicSeed || root */
		int n = params.getDigestSize();
		int indexSize = (int)Math.ceil(params.getTotalHeight() / (double) 8);
		int secretKeySize = n;
		int secretKeyPRFSize = n;
		int publicSeedSize = n;
		int rootSize = n;
		int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
		byte[] out = new byte[totalSize];
		int position = 0;
		/* copy index */
		byte[] indexBytes = XMSSUtil.toBytesBigEndian(globalIndex, indexSize);
		XMSSUtil.copyBytesAtOffset(out, indexBytes, position);
		position += indexSize;
		/* copy secretKeySeed */
		XMSSUtil.copyBytesAtOffset(out, secretKeySeed, position);
		position += secretKeySize;
		/* copy secretKeyPRF */
		XMSSUtil.copyBytesAtOffset(out, secretKeyPRF, position);
		position += secretKeyPRFSize;
		/* copy publicSeed */
		XMSSUtil.copyBytesAtOffset(out, publicSeed, position);
		position += publicSeedSize;
		/* copy root */
		XMSSUtil.copyBytesAtOffset(out, root, position);
		return out;
	}
	
	@Override
	public void parseByteArray(byte[] in) throws ParseException {
		if (in == null) {
			throw new NullPointerException("in == null");
		}
		int n = params.getDigestSize();
		int totalHeight = params.getTotalHeight();
		int indexSize = (int)Math.ceil(totalHeight / (double) 8);
		int secretKeySize = n;
		int secretKeyPRFSize = n;
		int publicSeedSize = n;
		int rootSize = n;
		int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
		if (in.length != totalSize) {
			throw new ParseException("private key has wrong size", 0);
		}
		int position = 0;
		globalIndex = XMSSUtil.bytesToXBigEndian(in, position, indexSize);
		if (!XMSSUtil.isIndexValid(totalHeight, globalIndex)) {
			throw new ParseException("index out of bounds", 0);
		}
		position += indexSize;
		secretKeySeed = XMSSUtil.extractBytesAtOffset(in, position, secretKeySize);
		position += secretKeySize;
		secretKeyPRF = XMSSUtil.extractBytesAtOffset(in, position, secretKeyPRFSize);
		position += secretKeyPRFSize;
		publicSeed = XMSSUtil.extractBytesAtOffset(in, position, publicSeedSize);
		position += publicSeedSize;
		root = XMSSUtil.extractBytesAtOffset(in, position, rootSize);
	}
	
	public long getGlobalIndex() {
		return globalIndex;
	}

	public void setGlobalIndex(long globalIndex) {
		this.globalIndex = globalIndex;
	}

	public byte[] getSecretKeySeed() {
		return secretKeySeed;
	}

	public void setSecretKeySeed(byte[] secretKeySeed) {
		this.secretKeySeed = secretKeySeed;
	}

	public byte[] getSecretKeyPRF() {
		return secretKeyPRF;
	}

	public void setSecretKeyPRF(byte[] secretKeyPRF) {
		this.secretKeyPRF = secretKeyPRF;
	}

	public byte[] getPublicSeed() {
		return publicSeed;
	}

	public void setPublicSeed(byte[] publicSeed) {
		this.publicSeed = publicSeed;
	}

	public byte[] getRoot() {
		return root;
	}

	public void setRoot(byte[] root) {
		this.root = root;
	}
}
