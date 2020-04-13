package org.crypto.sse;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import javax.crypto.NoSuchPaddingException;


public class DynRR {

	

	// ***********************************************************************************************//

	///////////////////// Setup /////////////////////////////

	// ***********************************************************************************************//

	

	public static Map<String, byte[]> updateToken(byte[] key, Map<String, String> lookup)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {


		Map<String, byte[]> tokenUp = new HashMap<String, byte[]>();

		SecureRandom random = new SecureRandom();
		random.setSeed(CryptoPrimitives.randomSeed(16));
		byte[] iv = new byte[16];

		for (String word : lookup.keySet()) { 

			byte[] key1 = CryptoPrimitives.generateHmac(key, 1 + word);

			byte[] key2 = CryptoPrimitives.generateHmac(key, 2 + word);
			
			byte[] label = CryptoPrimitives.generateHmac(key1, "" + 1);
			byte[] value = CryptoPrimitives.OTPEnc(key2, lookup.get(word));
		
			tokenUp.put(new String(label), value);
		}
		return tokenUp;
	}

	// ***********************************************************************************************//

	///////////////////// Update /////////////////////////////

	// ***********************************************************************************************//

	public static void update(ConcurrentMap<String, byte[]> dictionary, Map<String, byte[]> tokenUp) {

		for (String label : tokenUp.keySet()) {
			dictionary.put(label, tokenUp.get(label));
		}
	}

	// ***********************************************************************************************//

	///////////////////// Search token generation /////////////////////
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[][] searchToken(byte[] key, String word) throws UnsupportedEncodingException {

		byte[][] stk = new byte[2][];
		
		stk[0] = CryptoPrimitives.generateHmac(key, 1 + word);
		stk[1]= CryptoPrimitives.generateHmac(key, 2 + word);

		return stk;
	}

	// ***********************************************************************************************//

	///////////////////// Query algorithm /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] query(byte[] stk, ConcurrentMap<String, byte[]> dictionary)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		byte[] result = dictionary.get(new String(CryptoPrimitives.generateHmac(stk, "" + 1)));
		return result;
	}

	// ***********************************************************************************************//

	///////////////////// Delete token generation /////////////////////
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] delToken(byte[] key, String word) throws UnsupportedEncodingException {

		byte[] dtk = CryptoPrimitives.generateHmac(key, 1 + word);
		return dtk;
	}

	// ***********************************************************************************************//

	///////////////////// Deletion /////////////////////////////

	// ***********************************************************************************************//

	public static void delete(byte[] deltoken, List<Integer> indices, ConcurrentMap<String, byte[]> dictionary)
			throws UnsupportedEncodingException {

		// The indices selected by the client follows the order in the list
		dictionary.remove(new String(CryptoPrimitives.generateHmac(deltoken, "" + 1)));
		
	}

	// ***********************************************************************************************//

	///////////////////// Resolve Algorithm /////////////////////////////

	// ***********************************************************************************************//

	public static String resolve(byte[] key, byte[] ciphertext)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {


		String result = CryptoPrimitives.OTPDec(key, ciphertext);

		return result;
	}
}
