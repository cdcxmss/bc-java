package org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

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
     * Convert int/long to n-byte array.
     * @param value int/long value.
     * @param sizeInByte Size of byte array in byte.
     * @return int/long as big-endian byte array of size {@code sizeInByte}.
     */
    public static byte[] toBytesBigEndian(long value, int sizeInByte) {
    	byte[] out = new byte[sizeInByte];
    	for (int i = (sizeInByte - 1); i >= 0; i--) {
    		out[i] = (byte)value;
    		value >>>= 8;
    	}
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
    
	public static byte[][] cloneArray(byte[][] in) {
		byte[][] out = new byte[in.length][];
		for (int i = 0; i < in.length; i++) {
			out[i] = new byte[in[i].length];
			for (int j = 0; j < in[i].length; j++) {
				out[i][j] = in[i][j];
			}
		}
		return out;
	}
	
	/**
	 * Checks whether the digest is allowed according to draft-irtf-cfrg-xmss-hash-based-signatures-06.
	 * @param digest The digest to be validated.
	 * @return true if digest is valid false else.
	 */
	public static boolean isValidDigest(Digest digest) {
		if (digest instanceof SHA256Digest || digest instanceof SHA512Digest) {
			return true;
		}
		return false;
	}
	
	/**
	 * Concatenates an arbitrary number of byte arrays.
	 * @param arrays
	 * @return
	 */
	public static byte[] concat(byte[]... arrays) {
		int totalLength = 0;
	    for (int i = 0; i < arrays.length; i++)
	    {
	        totalLength += arrays[i].length;
	    }
	    byte[] result = new byte[totalLength];
	    int currentIndex = 0;
	    for (int i = 0; i < arrays.length; i++)
	    {
	        System.arraycopy(arrays[i], 0, result, currentIndex, arrays[i].length);
	        currentIndex += arrays[i].length;
	    }

	    return result;
	}
	
	public static Boolean compareByteArray(byte[] a, byte[] b) {
		if (a == null || b == null) {
			throw new NullPointerException("a or b == null");
		}
		if (a.length != b.length) {
			throw new IllegalArgumentException("size of a and b must be equal");
		}
		for (int i = 0; i < a.length; i++) {
			if (a[i] != b[i]) {
				return false;
			}
		}
		return true;
	}
}
