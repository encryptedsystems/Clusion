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
// This file mainly includes the implementation of Matryoshka filter which is a component of the ZMF encrypted multi map. It makes use of Bloom Filters and Online Ciphers
// In particular, we have the four algorithms for ZMF algorithm. This includes KeyGen, setup that builds of Matryoshka filters, a token algorithm and Test algorithm
// Updates:
// Use Setup, Token and test version 2 with optimized search and setup time
//***********************************************************************************************//
package org.crypto.sse;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class ZMF {

	// The keyHMAC enables the instantiation of the Random ORacle. There is no
	// need for keeping this key secret
	public static final byte[] keyHMAC = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
			0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

	// This list if used for testing purposes
	public static List<String> results = new ArrayList<String>();

	private ZMF() {
	}

	// ***********************************************************************************************//

	///////////////////// KeyGenSM /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] keyGenSM(int keySize, String password, String filePathString, int icount)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		File f = new File(filePathString);
		byte[] salt = null;

		if (f.exists() && !f.isDirectory()) {
			salt = CryptoPrimitives.readAlternateImpl(filePathString);
		} else {
			salt = CryptoPrimitives.randomBytes(8);
			CryptoPrimitives.write(salt, "saltSetM", "salt");

		}

		byte[] key = CryptoPrimitives.keyGenSetM(password, salt, icount, keySize);
		return key;

	}

	// ***********************************************************************************************//

	///////////////////// SetupSM /////////////////////////////

	// ***********************************************************************************************//

	public static List<boolean[]> setupSetM(byte[] key, String keyword, Multimap<String, String> documentsComposition,
			Multimap<String, String> keywordComposition, int maxLengthOfMask, int falsePosRate)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			IOException {

		// Extract all documents' identifiers that are associated to the keyword

		int identifierCounter = 0;
		int blockSize = 128;

		List<boolean[]> listOfBloomFilter = new ArrayList<boolean[]>();
		for (String identifier : keywordComposition.get(keyword)) {

			// Creation of ESet
			HashSet<Integer> state = new HashSet<Integer>();

			// Bloom Filter size setup such that it is a multiple of 2. This is
			// necessary when inserting the result of a hash which has a maximum
			// multiple of 2^x-1

			double arraySize = falsePosRate * documentsComposition.get(identifier).size() / Math.log(2);

			int counter = 0;
			for (int j = 0; j < 1000; j++) {
				if (arraySize > Math.pow(2, counter)) {
					counter++;
				} else {
					break;
				}
			}

			// Creation of the Bloom filter
			boolean[] bloomFilter = new boolean[(int) Math.pow(2, counter)];

			// Key of PRF applied to elements

			byte[] keyPRF = new byte[key.length / 3];
			System.arraycopy(key, 0, keyPRF, 0, key.length / 3);

			// Key for the online cipher

			byte[] keyOCHash = new byte[key.length / 3];
			System.arraycopy(key, key.length / 3, keyOCHash, 0, key.length / 3);

			byte[] keyOCEnc = new byte[key.length / 3];
			System.arraycopy(key, 2 * key.length / 3, keyOCEnc, 0, key.length / 3);

			// Second Step of Secure Set protocol
			for (String word : documentsComposition.get(identifier)) {

				// computation of the PRF based on CMAC-AES
				byte[] cmac = CryptoPrimitives.generateCmac(keyPRF, keyword + word);

				// computation of the Random oracle based H1 on HMAC-SHA256
				// computation of the Random oracle based H2 on HMAC-SHA256

				int position = 0;
				boolean mask;

				// False positive rate is the number of hash functions

				for (int i = 0; i < falsePosRate; i++) {
					byte[] hmac = CryptoPrimitives.generateHmac(keyHMAC,
							i + CryptoPrimitives.booleanToString(CryptoPrimitives.bytesToBoolean(cmac)));

					// We truncate the needed bits from the output of the HMAC
					// to get the bit 1 to counter

					position = CryptoPrimitives.getIntFromByte(hmac, maxLengthOfMask);
					if (!state.contains(position)) {
						// Transform the position into an array of boolean []
						boolean[] messageBol = CryptoPrimitives.intToBoolean(position, maxLengthOfMask);

						boolean[][] results = CryptoPrimitives.onlineCipher(keyOCHash, keyOCEnc, messageBol);

						// System.out.println("Time of the OCs "+
						// messageBol.length+ " "+(endTime-startTime)+ "
						// "+(endTime1-startTime1));

						boolean[] positionFinal = new boolean[counter * blockSize];

						for (int s = 0; s < counter; s++) {
							System.arraycopy(results[s], 0, positionFinal, s * blockSize, blockSize);
						}

						byte[] hmac2 = CryptoPrimitives.generateHmac(keyHMAC,
								identifierCounter + CryptoPrimitives.booleanToString(positionFinal));

						// We truncate the needed bits from the output of the
						// HMAC to get the bit 1 to counter
						mask = (CryptoPrimitives.getBit(hmac2, 0) != 0);

						int pos = CryptoPrimitives.getIntFromByte(hmac, counter);
						bloomFilter[pos] = true ^ mask;
						state.add(pos);
					}

				}
			}

			for (int j = 0; j < bloomFilter.length; j++) {

				if (!state.contains(j)) {
					boolean[] messageBol = CryptoPrimitives.intToBoolean(j, maxLengthOfMask);
					boolean[][] results = CryptoPrimitives.onlineCipher(keyOCHash, keyOCEnc, messageBol);
					boolean[] positionFinal = new boolean[counter * blockSize];
					for (int s = 0; s < counter; s++) {
						System.arraycopy(results[s], 0, positionFinal, s * blockSize, blockSize);
					}

					byte[] hmac3 = CryptoPrimitives.generateHmac(keyHMAC,
							identifierCounter + CryptoPrimitives.booleanToString(positionFinal));

					bloomFilter[j] = false ^ (CryptoPrimitives.getBit(hmac3, 0) != 0);

				}
			}

			listOfBloomFilter.add(bloomFilter);

			identifierCounter++;

		}

		return listOfBloomFilter;
	}

	/*
	 * The version 2 of Setup handles the OC evaluation in a much faster way
	 * where the client will store in the setup phase all possible evaluations
	 * for the largest BF and will truncate these pre-computed values when
	 * required. The first version of Setup was computing the OC for every BF
	 * which was redundant.
	 */

	// ***********************************************************************************************//

	///////////////////// SetupSM /////////////////////////////

	// ***********************************************************************************************//

	public static Map<String, boolean[]> setupSetMV2(byte[] key, String keyword,
			Multimap<String, String> documentsComposition, Multimap<String, String> keywordComposition,
			int falsePosRate) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, IOException {

		// Extract all documents' identifiers that are associated to the keyword

		// Initialize a set that will contain all elements

		Multimap<String, String> totalElements = ArrayListMultimap.create();

		int maxSize = 0;
		Map<String, Map<Integer, Boolean>> state = new HashMap<String, Map<Integer, Boolean>>();

		// Create a Set that contains all elements of documents that contain
		// "keyword"
		for (String identifier : keywordComposition.get(keyword)) {

			// Filtering the keywords that are associated to a large number of
			// keywords
			for (String word : documentsComposition.get(identifier)) {
				if (!totalElements.get(word).contains(identifier) && ((double) TextExtractPar.lp1.get(word).size()
						/ TextExtractPar.maxTupleSize > IEXZMF.filterParameter)) {
					totalElements.put(word, identifier);
				}
			}

			if (documentsComposition.get(identifier).size() > maxSize) {
				maxSize = documentsComposition.get(identifier).size();
			}

			state.put(identifier, new HashMap<Integer, Boolean>());

		}

		// This can be used to reduce the size of the Bloom filters to store
		// only significant keywords

		// Limiting to a number of 1000 keywords per file

		// maxSize =1000;

		// determine the size of the largest array

		double maxArraySize = falsePosRate * maxSize / Math.log(2);

		// Creation of an array that has as a size a power of 2
		int counter = 0;
		for (int j = 0; j < 1000; j++) {
			if (maxArraySize > Math.pow(2, counter)) {
				counter++;
			} else {
				break;
			}
		}

		// The final size of the array equals
		maxArraySize = Math.pow(2, counter);

		// Key of PRF applied to elements

		byte[] keyPRF = new byte[key.length / 3];

		System.arraycopy(key, 0, keyPRF, 0, key.length / 3);

		// System.out.println("Key PRF "+
		// CryptoPrimitives.booleanToString(CryptoPrimitives.bytesToBoolean(keyPRF)));

		// Key for the online cipher

		byte[] keyOCHash = new byte[key.length / 3];
		System.arraycopy(key, key.length / 3, keyOCHash, 0, key.length / 3);

		byte[] keyOCEnc = new byte[key.length / 3];
		System.arraycopy(key, 2 * key.length / 3, keyOCEnc, 0, key.length / 3);

		// Creation of online Cipher values in memory

		List<byte[][]> onlineCipherList = new ArrayList<byte[][]>();

		for (int i = 0; i < maxArraySize; i++) {

			boolean[] messageBol = CryptoPrimitives.intToBoolean(i, counter);
			onlineCipherList.add(CryptoPrimitives.onlineCipherOWF(keyOCHash, keyOCEnc, messageBol));

		}

		// Block Size of the OC in bytes

		int blockSize = 32;

		// Initialization of all Matryoshka filters

		boolean mask;

		Map<String, boolean[]> listOfBloomFilter = new HashMap<String, boolean[]>();

		for (String identifier : keywordComposition.get(keyword)) {

			// determine the size of the Matryoshka filter
			int count = 0;
			double filterSize = 0;

			// MF each has a size at most maxSize
			if (documentsComposition.get(identifier).size() < maxSize) {
				filterSize = falsePosRate * documentsComposition.get(identifier).size() / Math.log(2);
			} else {
				filterSize = falsePosRate * maxSize / Math.log(2);
			}

			// Assuming of course that there is no filter with more than 2^1000
			// cells
			for (int j = 0; j < 1000; j++) {
				if (filterSize > Math.pow(2, count)) {
					count++;
				} else {
					break;
				}
			}
			// creation of an empty filter
			boolean[] bloomFilter = new boolean[(int) Math.pow(2, count)];

			// initialization of the state

			for (int v = 0; v < Math.pow(2, count); v++) {
				state.get(identifier).put(v, false);

			}

			// Adding the mask to all positions of the filter
			for (int j = 0; j < (int) Math.pow(2, count); j++) {

				// Truncating only the required position from the OC
				byte[] positionFinal = new byte[count * blockSize];

				for (int s = 0; s < count; s++) {
					System.arraycopy(onlineCipherList.get(j)[s], 0, positionFinal, s * blockSize, blockSize);
				}

				// Computing the Random Oracle

				byte[] hmac2 = CryptoPrimitives.generateHmac(keyHMAC,
						CryptoPrimitives.concat(identifier.getBytes(), positionFinal));

				// We truncate the needed bits from the output of the HMAC to
				// get the bit 1 to counter
				mask = (CryptoPrimitives.getBit(hmac2, 0) != 0);
				bloomFilter[j] = mask;
			}

			listOfBloomFilter.put(identifier, bloomFilter);

		}

		// Insertion of the elements in the filters

		for (String word : totalElements.keySet()) {

			for (String id : totalElements.get(word)) {

				// determine the size of the Matryoshka filter
				int count = 0;
				// double filterSize= falsePosRate *
				// documentsComposition.get(id).size()/Math.log(2);
				double filterSize = 0;
				if (documentsComposition.get(id).size() < maxSize) {
					filterSize = falsePosRate * documentsComposition.get(id).size() / Math.log(2);
				} else {
					filterSize = falsePosRate * maxSize / Math.log(2);
				}

				for (int j = 0; j < 1000; j++) {
					if (filterSize > Math.pow(2, count)) {
						count++;
					} else {
						break;
					}
				}

				for (int j = 0; j < falsePosRate; j++) {

					// Computation of the position where the element will be
					// inserted
					byte[] hmac = CryptoPrimitives.generateHmac(keyHMAC,
							CryptoPrimitives.concat(String.valueOf(j).getBytes(), CryptoPrimitives.generateHmac(keyPRF,
									CryptoPrimitives.concat(keyword.getBytes(), word.getBytes()))));

					int pos = CryptoPrimitives.getIntFromByte(hmac, count);

					if (state.get(id).get(pos).equals(false)) {

						boolean[] temp = listOfBloomFilter.get(id);
						temp[pos] = true ^ temp[pos];
						listOfBloomFilter.put(id, temp);
						state.get(id).put(pos, true);

					}
				}
			}
		}

		return listOfBloomFilter;

	}

	// ***********************************************************************************************//

	///////////////////// GenTokSM without partitioning
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//
	public static List<byte[]> genTokSMV2(byte[] key, String keywordONE, String keywordTWO, int maxLengthOfMask,
			int falsePosRate) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, IOException {

		List<byte[]> token = new ArrayList<byte[]>();

		int blockSize = 32;

		// Key of PRF applied to elements

		byte[] keyPRF = new byte[key.length / 3];
		System.arraycopy(key, 0, keyPRF, 0, key.length / 3);

		// Key for the online cipher

		byte[] keyOCHash = new byte[key.length / 3];
		System.arraycopy(key, key.length / 3, keyOCHash, 0, key.length / 3);

		byte[] keyOCEnc = new byte[key.length / 3];
		System.arraycopy(key, 2 * key.length / 3, keyOCEnc, 0, key.length / 3);

		// computation of the PRF based on CMAC-AES
		byte[] cmac = CryptoPrimitives.generateHmac(keyPRF,
				CryptoPrimitives.concat(keywordONE.getBytes(), keywordTWO.getBytes()));

		token.add(cmac);

		int position = 0;

		// False positive rate is the number of hash functions

		for (int i = 0; i < falsePosRate; i++) {
			byte[] hmac = CryptoPrimitives.generateHmac(keyHMAC,
					CryptoPrimitives.concat(String.valueOf(i).getBytes(), cmac));
			// We truncate the needed bits from the output of the HMAC to get
			// the bit 1 to counter
			position = CryptoPrimitives.getIntFromByte(hmac, maxLengthOfMask);

			// Transform the position into an array of boolean []
			boolean[] messageBol = CryptoPrimitives.intToBoolean(position, maxLengthOfMask);

			byte[][] results = CryptoPrimitives.onlineCipherOWF(keyOCHash, keyOCEnc, messageBol);
			// Truncating only the required position from the OC
			byte[] positionFinal = new byte[maxLengthOfMask * blockSize];

			for (int s = 0; s < maxLengthOfMask; s++) {
				System.arraycopy(results[s], 0, positionFinal, s * blockSize, blockSize);
			}

			token.add(positionFinal);

		}
		return token;

	}

	// ***********************************************************************************************//

	///////////////////// TestSM without partitioning
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static boolean[] testSMV2(Map<String, boolean[]> listOfbloomFilter, List<byte[]> token, int ratePos)
			throws UnsupportedEncodingException {
		boolean[] result = new boolean[listOfbloomFilter.size()];
		results = new ArrayList<String>();
		// Fetch first the result of the PRF
		byte[] prf = token.get(0);

		int blockSize = 32;

		// For each Bloom filter compute whether or not the element exists
		int position;
		boolean mask;
		int counter = 0;
		for (String id : listOfbloomFilter.keySet()) {

			for (int j = 0; j < ratePos; j++) {

				byte[] hmac = CryptoPrimitives.generateHmac(keyHMAC,
						CryptoPrimitives.concat(String.valueOf(j).getBytes(), prf));

				int count = (int) (Math.log(listOfbloomFilter.get(id).length) / Math.log(2));

				// Truncating only the required position from the OC

				byte[] positionFinal = new byte[count * blockSize];

				System.arraycopy(token.get(j + 1), 0, positionFinal, 0, count * blockSize);

				// Computing the Random Oracle
				byte[] hmac2 = CryptoPrimitives.generateHmac(keyHMAC,
						CryptoPrimitives.concat(id.getBytes(), positionFinal));

				// We truncate the needed bits from the output of the HMAC to
				// get the bit 1 to counter
				mask = (CryptoPrimitives.getBit(hmac2, 0) != 0);

				// We truncate the needed bits from the output of the HMAC to
				// get the bit 1 to counter
				position = CryptoPrimitives.getIntFromByte(hmac, count);

				if (listOfbloomFilter.get(id)[position] ^ mask == true) {
					result[counter] = true;

				} else {
					result[counter] = false;
					break;
				}
			}

			if (result[counter] == true) {
				results.add(id);
			}

			counter++;

		}

		return result;
	}

	// ***********************************************************************************************//

	///////////////////// GenTokSM without partitioning
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//
	public static List<String> genTokSM(byte[] key, String keywordONE, String keywordTWO, int maxLengthOfMask,
			int falsePosRate) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, IOException {

		List<String> token = new ArrayList<String>();

		int blockSize = 128;

		// Key of PRF applied to elements

		byte[] keyPRF = new byte[key.length / 3];
		System.arraycopy(key, 0, keyPRF, 0, key.length / 3);

		// Key for the online cipher

		byte[] keyOCHash = new byte[key.length / 3];
		System.arraycopy(key, key.length / 3, keyOCHash, 0, key.length / 3);

		byte[] keyOCEnc = new byte[key.length / 3];
		System.arraycopy(key, 2 * key.length / 3, keyOCEnc, 0, key.length / 3);

		// computation of the PRF based on CMAC-AES
		byte[] cmac = CryptoPrimitives.generateCmac(keyPRF, keywordONE + keywordTWO);

		token.add(CryptoPrimitives.booleanToString(CryptoPrimitives.bytesToBoolean(cmac)));

		int position = 0;

		// False positive rate is the number of hash functions

		for (int i = 0; i < falsePosRate; i++) {
			byte[] hmac = CryptoPrimitives.generateHmac(keyHMAC,
					i + CryptoPrimitives.booleanToString(CryptoPrimitives.bytesToBoolean(cmac)));

			// We truncate the needed bits from the output of the HMAC to get
			// the bit 1 to counter
			position = CryptoPrimitives.getIntFromByte(hmac, maxLengthOfMask);

			// Transform the position into an array of boolean []
			boolean[] messageBol = CryptoPrimitives.intToBoolean(position, maxLengthOfMask);

			boolean[][] results = CryptoPrimitives.onlineCipher(keyOCHash, keyOCEnc, messageBol);
			boolean[] positionFinal = new boolean[maxLengthOfMask * blockSize];
			for (int s = 0; s < maxLengthOfMask; s++) {
				System.arraycopy(results[s], 0, positionFinal, s * blockSize, blockSize);
			}

			token.add(CryptoPrimitives.booleanToString(positionFinal));

		}
		return token;

	}

	// ***********************************************************************************************//

	///////////////////// TestSM without partitioning
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static boolean[] testSM(List<boolean[]> listOfbloomFilter, List<String> token, int ratePos)
			throws UnsupportedEncodingException {
		boolean[] result = new boolean[listOfbloomFilter.size()];

		// Fetch first the result of the PRF
		String prf = token.get(0);
		int blockSize = 128;

		// For each Bloom filter compute whether or not the element exists
		int position;
		boolean mask;
		for (int i = 0; i < listOfbloomFilter.size(); i++) {

			String truncatedTok = "";
			for (int j = 0; j < ratePos; j++) {

				byte[] hmac = CryptoPrimitives.generateHmac(keyHMAC, j + prf);

				// We truncate the needed bits from the output of the HMAC to
				// get the bit 1 to counter
				position = CryptoPrimitives.getIntFromByte(hmac,
						(int) (Math.log(listOfbloomFilter.get(i).length) / Math.log(2)));

				// Truncated Circular TOKEN

				truncatedTok = token.get(j + 1).substring(0,
						(int) (Math.log(listOfbloomFilter.get(i).length) / Math.log(2)) * blockSize);

				byte[] hmac3 = CryptoPrimitives.generateHmac(keyHMAC, i + truncatedTok);

				mask = (CryptoPrimitives.getBit(hmac3, 0) != 0);

				if (listOfbloomFilter.get(i)[position] ^ mask == true) {
					result[i] = true;

				} else {
					result[i] = false;
					break;
				}
			}

		}

		return result;
	}

}
