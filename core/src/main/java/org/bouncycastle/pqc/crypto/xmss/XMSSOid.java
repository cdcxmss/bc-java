package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * XMSSOid class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSOid {

	/**
	 * XMSS OID lookup table.
	 */
	private static final Map<String, XMSSOid> oidLookupTable;
	static {
		Map<String, XMSSOid> map = new HashMap<String, XMSSOid>();
		map.put(createKey("SHA-256", 32, 16, 67, 10), new XMSSOid(0x01000001, "XMSS_SHA2-256_W16_H10"));
		map.put(createKey("SHA-256", 32, 16, 67, 16), new XMSSOid(0x02000002, "XMSS_SHA2-256_W16_H16"));
		map.put(createKey("SHA-256", 32, 16, 67, 20), new XMSSOid(0x03000003, "XMSS_SHA2-256_W16_H20"));
		map.put(createKey("SHA-512", 64, 16, 131, 10), new XMSSOid(0x04000004, "XMSS_SHA2-512_W16_H10"));
		map.put(createKey("SHA-512", 64, 16, 131, 16), new XMSSOid(0x05000005, "XMSS_SHA2-512_W16_H16"));
		map.put(createKey("SHA-512", 64, 16, 131, 20), new XMSSOid(0x06000006, "XMSS_SHA2-512_W16_H20"));
		map.put(createKey("SHAKE128", 32, 16, 67, 10), new XMSSOid(0x07000007, "XMSS_SHAKE128_W16_H10"));
		map.put(createKey("SHAKE128", 32, 16, 67, 16), new XMSSOid(0x08000008, "XMSS_SHAKE128_W16_H16"));
		map.put(createKey("SHAKE128", 32, 16, 67, 20), new XMSSOid(0x09000009, "XMSS_SHAKE128_W16_H20"));
		map.put(createKey("SHAKE256", 64, 16, 131, 10), new XMSSOid(0x0a00000a, "XMSS_SHAKE256_W16_H10"));
		map.put(createKey("SHAKE256", 64, 16, 131, 16), new XMSSOid(0x0b00000b, "XMSS_SHAKE256_W16_H16"));
		map.put(createKey("SHAKE256", 64, 16, 131, 20), new XMSSOid(0x0c00000c, "XMSS_SHAKE256_W16_H20"));
		oidLookupTable = Collections.unmodifiableMap(map);
	}
	
	/**
	 * OID.
	 */
	private int oid;
	/**
	 * String representation of OID.
	 */
	private String stringRepresentation;
	/**
	 * Digest size.
	 */
	private int digestSize;
	
	/**
	 * Constructor...
	 * @param oid OID.
	 * @param stringRepresentation String representation of OID.
	 */
	private XMSSOid(int oid, String stringRepresentation) {
		super();
		this.oid = oid;
		this.stringRepresentation = stringRepresentation;
	}
	
	/**
	 * Lookup OID.
	 * @param algorithmName Algorithm name.
	 * @param winternitzParameter Winternitz parameter.
	 * @param height Binary tree height.
	 * @return XMSS OID if parameters were found, null else.
	 */
	public static XMSSOid lookup(String algorithmName, int digestSize, int winternitzParameter, int len, int height) {
		if (algorithmName == null) {
			throw new NullPointerException("algorithmName == null");
		}
		return oidLookupTable.get(createKey(algorithmName, digestSize, winternitzParameter, len, height));
	}
	
	/**
	 * Create a key based on parameters.
	 * @param algorithmName Algorithm name.
	 * @param winternitzParameter Winternitz Parameter.
	 * @param height Binary tree height.
	 * @return String representation of parameters for lookup table.
	 */
	private static String createKey(String algorithmName, int digestSize, int winternitzParameter, int len, int height) {
		if (algorithmName == null) {
			throw new NullPointerException("algorithmName == null");
		}
		return algorithmName + "-" + digestSize + "-" + winternitzParameter + "-" + len + "-" + height;
	}

	/**
	 * Getter OID.
	 * @return OID.
	 */
	public int getOid() {
		return oid;
	}

	@Override
	public String toString() {
		return stringRepresentation;
	}
}
