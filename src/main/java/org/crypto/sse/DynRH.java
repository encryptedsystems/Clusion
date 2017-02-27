/** * Copyright (C) 2016 Tarik Moataz
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//***********************************************************************************************//

/////////////////////    Implementation of a dynamic Forward Secure SSE (a variant of the Cash et al. NDSS'14)

/////////////////////				Response Hiding with add and delete operations					///////////

//***********************************************************************************************//	

package org.crypto.sse;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ExecutionException;

import javax.crypto.NoSuchPaddingException;

import com.google.common.collect.Multimap;
import com.google.common.collect.Ordering;
import com.google.common.collect.TreeMultimap;

public class DynRH {

	public HashMap<String, byte[]> dictionaryUpdates = new HashMap<String, byte[]>();
	// The state needs to be stored on the client side
	public static HashMap<String, Integer> state = new HashMap<String, Integer>();
	// This determines the padding used for the filenames
	public static int sizeOfFileIdentifer = 100;
	// This variable keeps track of the retrieved positions for eventual
	// deletions
	public static List<Integer> positions = new ArrayList<Integer>();

	// ***********************************************************************************************//

	///////////////////// SetupSI /////////////////////////////

	// ***********************************************************************************************//

	public static HashMap<String, byte[]> setup() {

		System.out.println("Initialization of the Updated Encrypted Dictionary\n");

		HashMap<String, byte[]> dictionaryUpdates = new HashMap<String, byte[]>();

		return dictionaryUpdates;
	}

	public static TreeMultimap<String, byte[]> tokenUpdate(byte[] key, Multimap<String, String> lookup)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		// We use a lexicographic sorted list such that the server
		// will not know any information of the inserted elements creation order
		TreeMultimap<String, byte[]> tokenUp = TreeMultimap.create(Ordering.natural(), Ordering.usingToString());

		// Key generation
		for (String word : lookup.keySet()) {

			byte[] key2 = CryptoPrimitives.generateCmac(key, 2 + word);
			// generate keys for response-hiding construction for SIV (Synthetic
			// IV)
			byte[] key3 = CryptoPrimitives.generateCmac(key, 3 + new String());

			byte[] key4 = CryptoPrimitives.generateCmac(key, 4 + word);

			byte[] key5 = CryptoPrimitives.generateCmac(key, 5 + word);

			for (String id : lookup.get(word)) {
				int counter = 0;

				if (state.get(word) != null) {
					counter = state.get(word);
				}

				state.put(word, counter + 1);

				byte[] l = CryptoPrimitives.generateCmac(key5, "" + counter);

				String value = new String(CryptoPrimitives.DTE_encryptAES_CTR_String(key3, key4, id, 20), "ISO-8859-1");

				tokenUp.put(new String(l), CryptoPrimitives.encryptAES_CTR_String(key2,
						CryptoPrimitives.randomBytes(16), value, sizeOfFileIdentifer));

			}

		}
		return tokenUp;
	}

	// ***********************************************************************************************//

	///////////////////// Update /////////////////////////////

	// ***********************************************************************************************//

	public static void update(HashMap<String, byte[]> dictionary, TreeMultimap<String, byte[]> tokenUp) {

		for (String label : tokenUp.keySet()) {
			dictionary.put(label, tokenUp.get(label).first());
		}
	}

	// ***********************************************************************************************//

	///////////////////// Search token generation /////////////////////
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[][] genToken(byte[] key, String word) throws UnsupportedEncodingException {

		byte[][] keys = new byte[2][];
		keys[0] = CryptoPrimitives.generateCmac(key, 5 + word);
		if (state.get(word) != null) {
			keys[1] = ByteBuffer.allocate(4).putInt(state.get(word)).array();
		} else {
			keys[1] = ByteBuffer.allocate(4).putInt(0).array();
		}

		return keys;
	}

	// ***********************************************************************************************//

	///////////////////// Query (test alg) /////////////////////////////

	// ***********************************************************************************************//

	public static List<byte[]> query(byte[][] keys, HashMap<String, byte[]> dictionaryUpdates)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		List<byte[]> result = new ArrayList<byte[]>();
		positions = new ArrayList<Integer>();
		for (int i = 0; i < ByteBuffer.wrap(keys[1]).getInt(); i++) {
			if (dictionaryUpdates.get(new String(CryptoPrimitives.generateCmac(keys[0], "" + i))) != null) {
				byte[] temp = dictionaryUpdates.get(new String(CryptoPrimitives.generateCmac(keys[0], "" + i)));
				// The "positions" list will only contain the counters for which
				// a value exists
				positions.add(i);
				result.add(temp);
			}
		}
		return result;
	}

	// ***********************************************************************************************//

	///////////////////// Delete token generation /////////////////////
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] delToken(byte[] key, String word) throws UnsupportedEncodingException {

		byte[] key1 = CryptoPrimitives.generateCmac(key, 5 + word);
		return key1;
	}

	// ***********************************************************************************************//

	///////////////////// Deletion /////////////////////////////

	// ***********************************************************************************************//

	public static void delete(byte[] key, List<Integer> indices, HashMap<String, byte[]> dictionaryUpdates)
			throws UnsupportedEncodingException {

		// The indices selected by the client follows the order in the list
		for (Integer id : indices) {
			dictionaryUpdates.remove(new String(CryptoPrimitives.generateCmac(key, "" + positions.get(id))));
		}
	}

	// ***********************************************************************************************//

	///////////////////// Decryption Algorithm /////////////////////////////

	// ***********************************************************************************************//

	public static List<String> resolve(byte[] key, List<byte[]> list, String keyword)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		byte[] key2 = CryptoPrimitives.generateCmac(key, 2 + keyword);
		byte[] key3 = CryptoPrimitives.generateCmac(key, 3 + new String());
		List<String> result = new ArrayList<String>();

		for (byte[] ct : list) {
			String decr = new String(CryptoPrimitives.decryptAES_CTR_String(ct, key2)).split("\t\t\t")[0];

			byte[] id2 = decr.getBytes("ISO-8859-1");

			result.add(new String(CryptoPrimitives.decryptAES_CTR_String(id2, key3)).split("\t\t\t")[0]);
		}

		return result;
	}

	// ***********************************************************************************************//

	///////////////////// Forward Secure versions /////////////////////////////

	// ***********************************************************************************************//

	///////////////////// Forward Secure Token generation /////////////////////
	///////////////////// ////////////////////////////

	// ***********************************************************************************************//

	public static byte[][] genTokenFS(byte[] key, String word) throws UnsupportedEncodingException {
		int counter = 0;
		if (state.get(word) != null) {
			counter = state.get(word);
		}

		byte[][] keys = new byte[counter][];
		byte[] temp = CryptoPrimitives.generateCmac(key, 5 + word);

		for (int i = 0; i < counter; i++) {
			keys[i] = CryptoPrimitives.generateCmac(temp, "" + i);
		}

		return keys;
	}

	// ***********************************************************************************************//

	///////////////////// Forward Secure Query /////////////////////////////

	// ***********************************************************************************************//

	public static List<byte[]> queryFS(byte[][] keys, HashMap<String, byte[]> dictionaryUpdates)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		List<byte[]> result = new ArrayList<byte[]>();

		for (int i = 0; i < keys.length; i++) {

			if (dictionaryUpdates.get(new String(keys[i])) != null) {
				byte[] temp = dictionaryUpdates.get(new String(keys[i]));
				// The "positions" list will only contain the counters for which
				// a value exists
				positions.add(i);
				result.add(temp);
			}
		}
		return result;
	}

	// ***********************************************************************************************//

	///////////////////// Forward Secure Delete token generation
	///////////////////// ///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[][] delTokenFS(byte[] key, String word, List<Integer> indices)
			throws UnsupportedEncodingException {

		byte[][] keys = new byte[indices.size()][];
		byte[] temp = CryptoPrimitives.generateCmac(key, 5 + word);

		for (int i = 0; i < indices.size(); i++) {
			keys[i] = CryptoPrimitives.generateCmac(temp, "" + positions.get(indices.get(i)));
		}

		return keys;
	}

	// ***********************************************************************************************//

	///////////////////// Forward Secure Deletion /////////////////////////////

	// ***********************************************************************************************//

	public static void deleteFS(byte[][] keys, HashMap<String, byte[]> dictionaryUpdates)
			throws UnsupportedEncodingException {

		// The indices selected by the client follows the order in the list
		for (int i = 0; i < keys.length; i++) {
			dictionaryUpdates.remove(new String(keys[i]));
		}
	}
}
