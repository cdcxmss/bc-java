package org.bouncycastle.pqc.crypto.test;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.xmss.NullPRNG;
import org.bouncycastle.pqc.crypto.xmss.WOTSPlusSignature;
import org.bouncycastle.pqc.crypto.xmss.XMSS;
import org.bouncycastle.pqc.crypto.xmss.XMSSNode;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSignature;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

/**
 * Test cases for XMSSSignature class.
 * 
 * @author Sebastian Roland <seroland86@gmail.com>
 */
public class XMSSSignatureTest extends TestCase {

	/*
	public void testSignatureParsing() {
		XMSSParameters params = new XMSSParameters(10, new SHA256Digest(), 16);
		XMSS xmss = new XMSS(params, new NullPRNG());
		XMSSSignature signature = new XMSSSignature(xmss);
		
		int n = xmss.getParams().getDigestSize();
		signature.setIndex(0xff);
		String random = "6945a6f13aa83e598cb8d0abebb5cddbd87e576226517f9001c1d36bb320bf80";
		byte[] randomByte = Hex.decode(random);
		signature.setRandom(randomByte);
		String[] wotsSignature = {
			"c20270a1e779fd234d57b893ca841994e128a6df3f1832eb5998b16e3273084c",
			"29c5107bb4d60539e2c35a47ea060c1d40bdb9df7a397c7d1b9e58bad2c4375e",
			"1837381b72f801f889b784bc13d0b92572f7fa9cce61441d36b25d20344f9f6e",
			"45a2aa2369c746b540b4573813c6ebf40344f7cd5ac7222d55d812dc3fd6f66a",
			"74b668afb0688c081c38d0db3bda3b42cf1025f2111e3b2c05a9552d6f2f39ac",
			"1a50e11cfddf56345c43a5eee163858ed56ca58656b5ba3c381bf1f307515488",
			"53b73d4d33493a3c1e957e6404e79d8129b6a19426551609f236760b17fbcd85",
			"36db642565a964f96ee40be0a75ab3ade6a952305655a8ba8b11ceca31bc37c5",
			"c1d257945dec4061a3eacb925a22960dc4f3187b5ba5b6f77721401a9699ceba",
			"b52b336fd16713cd5dd4c03e335369056c18d3c204686037ed4a04538f18715d",
			"1b0398312fa6eb9d15636e158a9ad3ef2d4acf0d62f9f465543f846d9d05573a",
			"0d2fb2ca57dec438768d018a086fde8ed65fbdc2ff6bd201dba997df199c049c",
			"52ae0baa3f5ed96488071cb9c0d71022649f218d1d911b146dee9d48b980a170",
			"4b19cd04daf37837836ea32e2d86afb3df8366a33fc27b081399d2b5ea511cdf",
			"cb6e2b9d18e1866e5726247cefe4a9eb25d5455d9849df5ee77a579fbd7d80cf",
			"ea74b74a7e249394421c3911d338f05c34ead8d8bf767563fc7eafb7e8d57d01",
			"7fa63bec0172ccbf085f02b417830c6a183d3ad504b8c3d3fbfe122fcfb6abcb",
			"e88965b603e625a3a178fa962a818b2373313c5a39f4f1e0233c96854456c2e4",
			"c742b2b518b95138050202921f7153ea59e3f2776138cdfe5ecdc16a94482527",
			"2ae1729515b0228aaf24487e9d8f46abe9f7c5026b564106f65ac09bc05ea3fd",
			"0ab74ec6989f0b683147662e8aecfe4494aa0ee80c298f8ce6ce29fb37a980ed",
			"f7fb9ca93bf41fc011887c63df168e3cf0da96249bb5e67e5fe8568c344f7e17",
			"be0cb6b976f99f3d1e58dbe34d9f94c714df3e3b3d0067c1de0b4b59a9a6a0be",
			"1329dcaf8181caf7412ee160aca1ed3c99932f6a673a08031a11bb64f641a272",
			"6e023a19472e7a5f175b2d09541b571f6f783c2213ed74bb3ca8b4e244f2282e",
			"24ccde41f8c589953970efe30dc65a0812f198ae3c4b50f5e85f9afaa13eb72f",
			"47b2f248aac34b47be2d47f756a7633071baf89593595a10373c385305f68520",
			"7d742b53af85731707aa8790fe40e1b06e1bf9efc9c6ca01ff879ff74729513d",
			"2e45683880ea5f69cd4ed302b434956195d481cd98a671afae0ea7f105238df3",
			"aabe89f938865808ea878b7d514523ece515025aa3cc10955f0d1b1015412c5d",
			"d2154baedec9d9ebf262ca81bf7739ad02cc6fd58924d0f526bc7da6cb7501de",
			"352c0f093786a28e793f70622d369e0f80091bebef052caec815b41923d0e459",
			"bb81bad1d761eb5f4dcd51549e7c64ba37dc3976838fe778540ddf264f071e9c",
			"e2dbe6600ac1bae7e23eb17b711622a92707fb0e2e960706b29a1e3e432e0c5c",
			"a60dd7df95a8892783fa22f271cd971531eb57ed67e31f07297b49f33672a223",
			"a8ab4e41f3ce546cc2a1f81cf040a82896f6d8419a5ad8f91e36aa1b89809a81",
			"2765ab31ba5a096e2a1596a1b06cbe867be177213d920fe60bf08d22b4dbaf8f",
			"38ffa48928bf438dc6359959431a610800bfaba35e82072558cef06dabeb2d08",
			"9113789c1604692f79ba30970acc34b2a96eb7f6d5ec7455d73c53a49e96ba23",
			"d42a8ccaf5c087377ad9ce9b1b9a870dfd045c21bd1040433bd5d6a880d9932f",
			"2ff302668439b5d567cb1ef3b78300244a15300898b0e1a63ecb817bc13dc576",
			"d20cb7521cf5f005944b15f57f3c41a9ad84ce85e5f0b7ccfcdda3b2043346ca",
			"5e9b817c8808a7c84753678b442f44668eac7ae1d8321eca933c5fd470b7587e",
			"ccc89a68f2a80b93bab05165ff668c34259754dcb10ab5ecb6f75e5459025408",
			"9bc163d6ba3c4512fafa5c7db05016f8922096ddd2923e1e3823fd8a1740854c",
			"3a837e5359681425913b4052daebde3963b4682bc8a4d977a50e02c44c3a4a7b",
			"f717995a5f6a2986e647dd52efc6a0b733b57f4008f8acfbe7737b65a525ba04",
			"a02a14c53cf9d56f6c369b602b1326e08126c932b379c960c6483f4d5e9cb489",
			"ad642cb63c02e2e64e6c13e1db105cdb5404883c3d46e96063bd4bb88a9ecfbc",
			"d4b7c8431abdfa7945727ef046208525c54c128679606af8b290d52d9e224803",
			"4d52c62e28baaa278167e8408763a2d00149e850be276e33f4f07593d5031c43",
			"8799b5e5fd0014437ad01691deb6e970fe429d0978a797e6b973c90cbe55f57f",
			"44b6a49df059adf75aff24adbf7efae31abc51ffa71cd9ad06f522c3609c7975",
			"dc09f02f9cfd31131c3e9b802d61e7c52e7b10918d7641ac9746a0b25f5f5a6e",
			"b70d4b9d2f740984d7b81ea164d0033838f3ae5395c17b56d55af6e599f720f0",
			"f5c598dda68cfdb70863b9864686389f55f3247d7600be994f8b6ea551834625",
			"4e10810c306f71ab303071c8003a283cc11d249dd20faeff769b75c2091049e9",
			"59803061fcb26c839b2ee8e83f302bfbef961ece8d2e33343665d3d28d88315e",
			"188e26e3501653210f374bc286fe1449742439051898958bb70181f4c764c785",
			"5d4e7594f782bb40ab97b39c739b30f336ef1f8600a7bb41c9bd9712890b0d48",
			"7a8fc413a00ca60fd6c29a0c5a07fe2f1832b2d76fe5ff588a8faee779a012e3",
			"5ea7a9018c12f6f52416f80129cc56ee2228948ba9c770360ec14b6ae840c74e",
			"acbc6edf48066f74a818011c332819d60bcd03101313fefef582e113a67ea971",
			"a207a315980c7ca76e27051b8b36d8c02388c6ce5c9e32f751565ab60f5b65ce",
			"ffd3c3ce9895271c12e80d05c3345cf0c8064bcd8a760ef3e534c06c3b02b992",
			"f4bccc3fc7ff364a07183b43a60cb6666ee69547ed53895f6be2083b11d50172",
			"46a103478034bf600f5f9f1d9130b6c3195f6165f3d050f794e7499f76814718"
		};
		byte[][] wotsSignatureBytes = new byte[wotsSignature.length][];
		for (int i = 0; i < wotsSignature.length; i++) {
			wotsSignatureBytes[i] = Hex.decode(wotsSignature[i]);
		}
		signature.setSignature(new WOTSPlusSignature(xmss.getWOTSPlus().getParams(), wotsSignatureBytes));
		
		String[] authPath = {
			"0b18461bf5d6e9b75df8f4205ed6b1588d78439ce8d034881da59738b2926ee1",
			"c8447cc55d958810077ea78a320999d8ab6b099519b3f94434544de1fe285855",
			"83ecfec1d70ddb97988e5993131ba5c68e64db569411a2a08b8d9cdc83f973c2",
			"596c8d7b891649449d422c9e8201bff41dce681c673f9d6e08a5ff0a15c4650f",
			"f7fcdb1f2bb82426951c84e60a793674a38253d317bfb08caf2f827bdb222473",
			"0cec23810e4950945fc77a2c0b4d0cc42b80566788eeacf82daf0b7c2597a972",
			"55bb77dbb7428d40a9c7a363416cc9c8099a9f7075ecca8e1e8152e1f832d1ab",
			"c614aae9c52ef7e187229ac00c0dd4366fe93fe39b80622d332e4cff3e9f5839"
		};
		
		List<XMSSNode> authPathList = new ArrayList<XMSSNode>();
		for (int i = 0; i < authPath.length; i++) {
			authPathList.add(new XMSSNode(0, Hex.decode(authPath[i])));
		}
		signature.setAuthPath(authPathList);
		
		byte[] dump = signature.toByteArray();
		XMSSSignature signature2 = new XMSSSignature(xmss);
		try {
			signature2.parseByteArray(dump);
		} catch (ParseException e) {
			e.printStackTrace();
			fail();
		}
		
		assertEquals(signature.getIndex(), signature2.getIndex());
		assertEquals(true, XMSSUtil.compareByteArray(signature.getRandom(), signature2.getRandom()));
		byte[] sig1 = signature.getSignature();
		byte[] sig2 = signature2.getSignature();
		assertEquals(true, XMSSUtil.compareByteArray(sig1, sig2));
		List<XMSSNode> authPath1 = signature.getAuthPath();
		List<XMSSNode> authPath2 = signature2.getAuthPath();
		assertEquals(authPath1.size(), authPath2.size());
		for (int i = 0; i < authPath1.size(); i++) {
			byte[] value1 = authPath1.get(i).getValue();
			byte[] value2 = authPath2.get(i).getValue();
			assertEquals(true, XMSSUtil.compareByteArray(value1, value2));
		}
	}
	*/
}
