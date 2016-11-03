package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.pqc.crypto.xmss.HashTreeAddress;
import org.bouncycastle.pqc.crypto.xmss.LTreeAddress;
import org.bouncycastle.pqc.crypto.xmss.OTSHashAddress;

import junit.framework.TestCase;

/**
 * Test cases for XMSSUtil class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSAddressTest extends TestCase {

	public void testOTSHashAddress() {
		OTSHashAddress address = new OTSHashAddress();
		assertEquals(0x00, address.getType());
		address.setLayerAddress(0x00);
		address.setTreeAddress(0x11);
		address.setOTSAddress(0x22);
		address.setChainAddress(0x33);
		address.setHashAddress(0x44);
		address.setKeyAndMask(0x55);
		byte[] out = address.toByteArray();
		assertEquals(0x00, out[0]);
		assertEquals(0x00, out[1]);
		assertEquals(0x00, out[2]);
		assertEquals(0x00, out[3]);
		assertEquals(0x00, out[4]);
		assertEquals(0x00, out[5]);
		assertEquals(0x00, out[6]);
		assertEquals(0x00, out[7]);
		assertEquals(0x00, out[8]);
		assertEquals(0x00, out[9]);
		assertEquals(0x00, out[10]);
		assertEquals(0x11, out[11]);
		assertEquals(0x00, out[12]);
		assertEquals(0x00, out[13]);
		assertEquals(0x00, out[14]);
		assertEquals(0x00, out[15]);
		assertEquals(0x00, out[16]);
		assertEquals(0x00, out[17]);
		assertEquals(0x00, out[18]);
		assertEquals(0x22, out[19]);
		assertEquals(0x00, out[20]);
		assertEquals(0x00, out[21]);
		assertEquals(0x00, out[22]);
		assertEquals(0x33, out[23]);
		assertEquals(0x00, out[24]);
		assertEquals(0x00, out[25]);
		assertEquals(0x00, out[26]);
		assertEquals(0x44, out[27]);
		assertEquals(0x00, out[28]);
		assertEquals(0x00, out[29]);
		assertEquals(0x00, out[30]);
		assertEquals(0x55, out[31]);
	}
	
	public void testLTreeAddress() {
		LTreeAddress address = new LTreeAddress();
		assertEquals(0x01, address.getType());
		address.setLayerAddress(0x00);
		address.setTreeAddress(0x11);
		address.setLTreeAddress(0x22);
		address.setTreeHeight(0x33);
		address.setTreeIndex(0x44);
		address.setKeyAndMask(0x55);
		byte[] out = address.toByteArray();
		assertEquals(0x00, out[0]);
		assertEquals(0x00, out[1]);
		assertEquals(0x00, out[2]);
		assertEquals(0x00, out[3]);
		assertEquals(0x00, out[4]);
		assertEquals(0x00, out[5]);
		assertEquals(0x00, out[6]);
		assertEquals(0x00, out[7]);
		assertEquals(0x00, out[8]);
		assertEquals(0x00, out[9]);
		assertEquals(0x00, out[10]);
		assertEquals(0x11, out[11]);
		assertEquals(0x00, out[12]);
		assertEquals(0x00, out[13]);
		assertEquals(0x00, out[14]);
		assertEquals(0x01, out[15]);
		assertEquals(0x00, out[16]);
		assertEquals(0x00, out[17]);
		assertEquals(0x00, out[18]);
		assertEquals(0x22, out[19]);
		assertEquals(0x00, out[20]);
		assertEquals(0x00, out[21]);
		assertEquals(0x00, out[22]);
		assertEquals(0x33, out[23]);
		assertEquals(0x00, out[24]);
		assertEquals(0x00, out[25]);
		assertEquals(0x00, out[26]);
		assertEquals(0x44, out[27]);
		assertEquals(0x00, out[28]);
		assertEquals(0x00, out[29]);
		assertEquals(0x00, out[30]);
		assertEquals(0x55, out[31]);
	}
	
	public void testHashTreeAddress() {
		HashTreeAddress address = new HashTreeAddress();
		assertEquals(0x02, address.getType());
		address.setLayerAddress(0x00);
		address.setTreeAddress(0x11);
		address.setTreeHeight(0x33);
		address.setTreeIndex(0x44);
		address.setKeyAndMask(0x55);
		byte[] out = address.toByteArray();
		assertEquals(0x00, out[0]);
		assertEquals(0x00, out[1]);
		assertEquals(0x00, out[2]);
		assertEquals(0x00, out[3]);
		assertEquals(0x00, out[4]);
		assertEquals(0x00, out[5]);
		assertEquals(0x00, out[6]);
		assertEquals(0x00, out[7]);
		assertEquals(0x00, out[8]);
		assertEquals(0x00, out[9]);
		assertEquals(0x00, out[10]);
		assertEquals(0x11, out[11]);
		assertEquals(0x00, out[12]);
		assertEquals(0x00, out[13]);
		assertEquals(0x00, out[14]);
		assertEquals(0x02, out[15]);
		assertEquals(0x00, out[16]);
		assertEquals(0x00, out[17]);
		assertEquals(0x00, out[18]);
		assertEquals(0x00, out[19]);
		assertEquals(0x00, out[20]);
		assertEquals(0x00, out[21]);
		assertEquals(0x00, out[22]);
		assertEquals(0x33, out[23]);
		assertEquals(0x00, out[24]);
		assertEquals(0x00, out[25]);
		assertEquals(0x00, out[26]);
		assertEquals(0x44, out[27]);
		assertEquals(0x00, out[28]);
		assertEquals(0x00, out[29]);
		assertEquals(0x00, out[30]);
		assertEquals(0x55, out[31]);
	}
}
