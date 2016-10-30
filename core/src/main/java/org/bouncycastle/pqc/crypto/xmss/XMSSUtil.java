package org.bouncycastle.pqc.crypto.xmss;
/**
 * Utils for XMSS implementation
 */
public class XMSSUtil {

	/**
	 * Calculates the logarithm base 2 for a given Integer.
	 */
    public static int log2(int n) {
        int log = 0;
        while ((n >>= 1) != 0) {
            log++;
        }
        return log;
    }
    
    /**
     * Returns a sizeInByte-byte string from an Integer in big-endian byte order.
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
