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

/////////////////////				Response Hiding with add operations					///////////

//***********************************************************************************************//	

package org.crypto.sse;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ExecutionException;

import javax.crypto.NoSuchPaddingException;

import com.google.common.collect.Multimap;
import com.google.common.collect.Ordering;
import com.google.common.collect.TreeMultimap;

public class DynRH2Lev extends RH2Lev {

	public HashMap<String, byte[]> dictionaryUpdates = new HashMap<String, byte[]>();
	public static HashMap<String, Integer> state = new HashMap<String, Integer>();

	public DynRH2Lev(Multimap<String, byte[]> dictionary, byte[][] arr, HashMap<String, byte[]> dictionaryUpdates) {
		super(dictionary, arr);
		// TODO Auto-generated constructor stub
		this.dictionaryUpdates = dictionaryUpdates;

	}

	public HashMap<String, byte[]> getDictionaryUpdates() {
		return dictionaryUpdates;
	}

	// ***********************************************************************************************//

	///////////////////// Setup /////////////////////////////

	// ***********************************************************************************************//

	public static DynRH2Lev constructEMMParGMM(final byte[] key, final Multimap<String, String> lookup,
			final int bigBlock, final int smallBlock, final int dataSize)
			throws InterruptedException, ExecutionException, IOException {

		RH2Lev result = constructEMMPar(key, lookup, bigBlock, smallBlock, dataSize);

		System.out.println("Initialization of the Encrypted Dictionary that will handle the updates:\n");

		HashMap<String, byte[]> dictionaryUpdates = new HashMap<String, byte[]>();

		return new DynRH2Lev(result.getDictionary(), result.getArray(), dictionaryUpdates);
	}

	// ***********************************************************************************************//

	///////////////////// Update Token /////////////////////////////

	// ***********************************************************************************************//

	public static TreeMultimap<String, byte[]> tokenUpdate(byte[] key, Multimap<String, String> lookup)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		TreeMultimap<String, byte[]> tokenUp = TreeMultimap.create(Ordering.natural(), Ordering.usingToString());

		SecureRandom random = new SecureRandom();
		random.setSeed(CryptoPrimitives.randomSeed(16));
		byte[] iv = new byte[16];

		for (String word : lookup.keySet()) {

			byte[] key3 = CryptoPrimitives.generateCmac(key, 3 + new String());

			byte[] key4 = CryptoPrimitives.generateCmac(key, 4 + word);

			for (String id : lookup.get(word)) {
				random.nextBytes(iv);

				int counter = 0;

				if (state.get(word) != null) {
					counter = state.get(word);
				}

				state.put(word, counter + 1);

				byte[] l = CryptoPrimitives.generateCmac(key4, "" + counter);

				byte[] value = CryptoPrimitives.encryptAES_CTR_String(key3, iv, id, sizeOfFileIdentifer);

				tokenUp.put(new String(l), value);
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

	///////////////////// Search Token /////////////////////
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[][] genToken(byte[] key, String word) throws UnsupportedEncodingException {

		byte[][] keys = new byte[4][];
		keys[0] = CryptoPrimitives.generateCmac(key, 1 + word);
		keys[1] = CryptoPrimitives.generateCmac(key, 2 + word);
		keys[2] = CryptoPrimitives.generateCmac(key, 4 + word);
		if (state.get(word) != null) {
			keys[3] = ByteBuffer.allocate(4).putInt(state.get(word)).array();
		} else {
			keys[3] = ByteBuffer.allocate(4).putInt(0).array();
		}

		return keys;
	}

	// ***********************************************************************************************//

	///////////////////// Test /////////////////////////////

	// ***********************************************************************************************//

	public static List<String> query(byte[][] keys, Multimap<String, byte[]> dictionary, byte[][] array,
			HashMap<String, byte[]> dictionaryUpdates) throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {

		List<String> result = query(keys, dictionary, array);

		for (int i = 0; i < ByteBuffer.wrap(keys[3]).getInt(); i++) {
			byte[] temp = dictionaryUpdates.get(new String(CryptoPrimitives.generateCmac(keys[2], "" + i)));
			result.add(new String(temp, "ISO-8859-1"));
		}
		return result;
	}

	// ***********************************************************************************************//

	///////////////////// Forward Secure versions /////////////////////////////

	// ***********************************************************************************************//

	///////////////////// Forward Secure Token generation /////////////////////
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[][] genTokenFS(byte[] key, String word) throws UnsupportedEncodingException {
		int counter = 0;
		if (state.get(word) != null) {
			counter = state.get(word);
		}

		byte[][] keys = new byte[2 + counter][];
		keys[0] = CryptoPrimitives.generateCmac(key, 1 + word);
		keys[1] = CryptoPrimitives.generateCmac(key, 2 + word);
		byte[] temp = CryptoPrimitives.generateCmac(key, 4 + word);

		for (int i = 0; i < counter; i++) {
			keys[2 + i] = CryptoPrimitives.generateCmac(temp, "" + i);
		}

		return keys;
	}

	// ***********************************************************************************************//

	///////////////////// Forward Secure Query /////////////////////////////

	// ***********************************************************************************************//

	public static List<String> queryFS(byte[][] keys, Multimap<String, byte[]> dictionary, byte[][] array,
			HashMap<String, byte[]> dictionaryUpdates) throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {

		List<String> result = query(keys, dictionary, array);

		for (int i = 0; i < keys.length - 2; i++) {
			byte[] temp = dictionaryUpdates.get(new String(keys[2 + i]));
			result.add(new String(temp, "ISO-8859-1"));
		}
		return result;
	}

}
