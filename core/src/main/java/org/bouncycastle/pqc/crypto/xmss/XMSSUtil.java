package org.bouncycastle.pqc.crypto.xmss;
/**
 * 
 * Utils for XMSS implementation.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 * @author Niklas Bunzel <niklas.bunzel@gmx.de>
 */
public class XMSSUtil {

	/**
	 * Calculates the logarithm base 2 for a given Integer.
	 * @param n Number.
	 * @return Logarithm to base 2 of {@code n}.
	 */
    public static int log2(int n) {
        int log = 0;
        while ((n >>= 1) != 0) {
            log++;
        }
        return log;
    }
    
    /**
     * Convert Integer to byte array.
     * @param value Integer value.
     * @param sizeInByte Size of byte array in byte.
     * @return Integer as big-endian byte array of size {@code sizeInByte}.
     */
    public static byte[] intToBytesBigEndian(int value, int sizeInByte) {
    	if (sizeInByte < 4) {
    		throw new IllegalArgumentException("size has to be at least as big as size of integer");
    	}
    	byte[] out = new byte[sizeInByte];
    	int startIndex = sizeInByte - 4;
    	out[startIndex] = (byte)((value >> 24) & 0xff);
    	out[startIndex + 1] = (byte)((value >> 16) & 0xff);
    	out[startIndex + 2] = (byte)((value >> 8) & 0xff);
    	out[startIndex + 3] = (byte)((value) & 0xff);
    	return out;
    }
}
