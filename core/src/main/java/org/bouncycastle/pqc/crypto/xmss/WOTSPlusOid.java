package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * WOTS+ OID class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class WOTSPlusOid {

	/**
	 * XMSS OID lookup table.
	 */
	private static final Map<String, WOTSPlusOid> oidLookupTable;
	static {
		Map<String, WOTSPlusOid> map = new HashMap<String, WOTSPlusOid>();
		map.put(createKey("SHA-256", 16), new WOTSPlusOid(0x01000001, "WOTSP_SHA2-256_W16"));
		map.put(createKey("SHA-512", 16), new WOTSPlusOid(0x02000002, "WOTSP_SHA2-512_W16"));
		/*
		map.put(getKey("SHAKE128", 16), new WOTSPlusOid(0x03000003, "XMSS_SHAKE128_W16_H10"));
		map.put(getKey("SHAKE256", 16), new WOTSPlusOid(0x04000004, "XMSS_SHAKE256_W16_H10"));
		*/
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
	 * Constructor...
	 * @param oid OID.
	 * @param stringRepresentation String representation of OID.
	 */
	private WOTSPlusOid(int oid, String stringRepresentation) {
		super();
		this.oid = oid;
		this.stringRepresentation = stringRepresentation;
	}
	
	/**
	 * Lookup OID.
	 * @param algorithmName Algorithm name.
	 * @param winternitzParameter Winternitz parameter.
	 * @return WOTS+ OID if parameters were found, null else.
	 */
	protected static WOTSPlusOid lookup(String algorithmName, int winternitzParameter) {
		if (algorithmName == null) {
			throw new NullPointerException("algorithmName == null");
		}
		return oidLookupTable.get(createKey(algorithmName, winternitzParameter));
	}
	
	/**
	 * Create a key based on parameters.
	 * @param algorithmName Algorithm name.
	 * @param winternitzParameter Winternitz Parameter.
	 * @return String representation of parameters for lookup table.
	 */
	private static String createKey(String algorithmName, int winternitzParameter) {
		if (algorithmName == null) {
			throw new NullPointerException("algorithmName == null");
		}
		return algorithmName + "-" + winternitzParameter;
	}

	/**
	 * Getter OID.
	 * @return OID.
	 */
	protected int getOid() {
		return oid;
	}

	@Override
	public String toString() {
		return stringRepresentation;
	}
}
