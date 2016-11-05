package org.bouncycastle.pqc.crypto.xmss;
/**
 * 
 * Utils for XMSS implementation.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
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
     * Convert int to n-byte array.
     * @param value Integer value.
     * @param sizeInByte Size of byte array in byte.
     * @return Integer as big-endian byte array of size {@code sizeInByte}.
     */
    public static byte[] intToBytesBigEndian(int value, int sizeInByte) {
    	if (sizeInByte < 4) {
    		throw new IllegalArgumentException("size has to be at least as big as size of integer");
    	}
    	byte[] out = new byte[sizeInByte];
    	intToBytesBigEndianOffset(out, value, sizeInByte - 4);
    	return out;
    }

    /**
     * Convert long to n-byte array.
     * @param value Long value.
     * @param sizeInByte Size of byte array in byte.
     * @return Long as big-endian byte array of size {@code sizeInByte}.
     */
    public static byte[] longToBytesBigEndian(long value, int sizeInByte) {
    	if (sizeInByte < 8) {
    		throw new IllegalArgumentException("size has to be at least as big as size of long");
    	}
    	byte[] out = new byte[sizeInByte];
    	longToBytesBigEndianOffset(out, value, sizeInByte - 8);
    	return out;
    }

    /**
     * Copy int to byte array in big-endian at specific offset.
     * @param Byte array.
     * @param Integer to put.
     * @param Offset in {@code in}.
     */
    public static void intToBytesBigEndianOffset(byte[] in, int value, int offset) {
    	if ((in.length - offset) < 4) {
    		throw new IllegalArgumentException("not enough space in array");
    	}
    	in[offset] = (byte)((value >> 24) & 0xff);
    	in[offset + 1] = (byte)((value >> 16) & 0xff);
    	in[offset + 2] = (byte)((value >> 8) & 0xff);
    	in[offset + 3] = (byte)((value) & 0xff);
    }
    
    /**
     * Copy long to byte array in big-endian at specific offset.
     * @param Byte array.
     * @param Long to put.
     * @param Offset in {@code in}.
     */
    public static void longToBytesBigEndianOffset(byte[] in, long value, int offset) {
    	if ((in.length - offset) < 8) {
    		throw new IllegalArgumentException("not enough space in array");
    	}
    	in[offset] = (byte)((value >> 56) & 0xff);
    	in[offset + 1] = (byte)((value >> 48) & 0xff);
    	in[offset + 2] = (byte)((value >> 40) & 0xff);
    	in[offset + 3] = (byte)((value >> 32) & 0xff);
    	in[offset + 4] = (byte)((value >> 24) & 0xff);
    	in[offset + 5] = (byte)((value >> 16) & 0xff);
    	in[offset + 6] = (byte)((value >> 8) & 0xff);
    	in[offset + 7] = (byte)((value) & 0xff);
    }
    
    /**
     * Convert from big endian byte array to int.
     * @param 4 byte array.
     * @return Integer.
     */
    public static int bytesToIntBigEndian(byte[] in, int offset) {
		if ((offset + 4) > in.length) {
			throw new IllegalArgumentException("out of bounds");
		}
		return (int)bytesToXBigEndian(in, offset, 4);
	}
	
    /**
     * Convert from big endian byte array to long.
     * @param 4 byte array.
     * @return Long.
     */
    public static long bytesToLongBigEndian(byte[] in, int offset) {
		if ((offset + 8) > in.length) {
			throw new IllegalArgumentException("out of bounds");
		}
		return bytesToXBigEndian(in, offset, 8);
	}
    
    /**
     * Generic convert from big endian byte array to long.
     * @param x-byte array
     * @param offset.
     * @param size.
     * @return Long.
     */
    private static long bytesToXBigEndian(byte[] in, int offset, int size) {
		long res = 0;
		for (int i = offset; i < (offset + size); i++) {
		   res = (res << 8) | (in[i] & 0xff);
		}
		return res;
    }
}
