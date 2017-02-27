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

// This file contains the encrypted multi-map encryption scheme by Cash, Jarecki, Jutla, Krawczyk, Rosu, Steiner Crypto'13: implementating their proposed TSet:
// KeyGen, Setup, Token and Test algorithms. 
//***********************************************************************************************//	

package org.crypto.sse;

import com.google.common.collect.Multimap;

import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.*;

public class TSet {

	public final static int spaceOverhead = 2;
	public final static int subBucketSize = 200;
	public static int bucketSize = 0;
	public static List<List<Integer>> free = new ArrayList<List<Integer>>();
	static List<List<Record>> secureIndex = new ArrayList<List<Record>>();

	// security parameter in bytes

	public static int securityParameter = 16;

	// Here we need 1 byte for beta, 16 bytes for the IV, 60 bytes for the
	// identifier and 10 bytes for the SecureSetM identifier
	public static int valueSize = 87;

	// Not necessary private, just used for the instantiation of the HMAC

	public static final byte[] keyHMACSI = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
			0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

	// ***********************************************************************************************//

	///////////////////// Key Generation /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] keyGen(int keySize, String password, String filePathString, int icount)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		File f = new File(filePathString);
		byte[] salt = null;

		if (f.exists() && !f.isDirectory()) {
			salt = CryptoPrimitives.readAlternateImpl(filePathString);
		} else {
			salt = CryptoPrimitives.randomBytes(8);
			CryptoPrimitives.write(salt, "saltInvIX", "salt");

		}

		byte[] key = CryptoPrimitives.keyGenSetM(password, salt, icount, keySize);
		return key;

	}

	// ***********************************************************************************************//

	///////////////////// Setup without partitioning /////////////////////
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static int setup(byte[] key1, byte[] key2, byte[] keyENC, String[] listOfKeyword,
			Multimap<String, String> lookup, Multimap<String, String> encryptedIdToRealId)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		int globalCounter = 0;
		for (String word : listOfKeyword) {

			// Computation of the keyword tag

			byte[] tag1 = CryptoPrimitives.generateCmac(key1, word);
			byte[] tag2 = CryptoPrimitives.generateCmac(key2, word);

			// Extraction of all documents identifiers associated to the word

			Collection<String> documents = lookup.get(word);

			int counter = 0;

			// initialize beta to be equal to zero
			int beta = 1;

			for (String id : documents) {

				// Compute the hash of the tag alongside with the counter

				byte[] hmac = CryptoPrimitives.concat(
						CryptoPrimitives.generateHmac512(keyHMACSI,
								Integer.toString(CryptoPrimitives.getIntFromByte(
										CryptoPrimitives.generateCmac(tag1, Integer.toString(counter)), 128))),
						CryptoPrimitives.generateHmac512(keyHMACSI, Integer.toString(CryptoPrimitives
								.getIntFromByte(CryptoPrimitives.generateCmac(tag2, Integer.toString(counter)), 128))));

				// Determine the needed number of bytes for the bucket
				// Divide the result of the hash in three different values

				int numberOfBytes = (int) Math.ceil((Math.log(bucketSize) / (Math.log(2) * 8)));

				byte[] bucket = new byte[numberOfBytes];

				byte[] labelAndValue = new byte[securityParameter + valueSize];
				System.arraycopy(hmac, 0, bucket, 0, bucket.length);
				System.arraycopy(hmac, bucket.length, labelAndValue, 0, labelAndValue.length);

				if (free.get(CryptoPrimitives.getIntFromByte(bucket, (int) (Math.log(bucketSize) / (Math.log(2)))))
						.isEmpty()) {
					System.out.println("Sub-Buckets are not big enough ==> re-do the process with a new key");
					System.exit(0);
				}

				// generate the integer which is associated to free[b]

				byte[] randomBytes = CryptoPrimitives.randomBytes((int) Math.ceil((Math.log(
						free.get(CryptoPrimitives.getIntFromByte(bucket, (int) (Math.log(bucketSize) / (Math.log(2)))))
								.size())
						/ (Math.log(2) * 8))));

				int position = CryptoPrimitives.getIntFromByte(randomBytes,
						(int) Math.ceil(Math.log(free.get(
								CryptoPrimitives.getIntFromByte(bucket, (int) (Math.log(bucketSize) / (Math.log(2)))))
								.size()) / Math.log(2)));

				while (position >= free
						.get(CryptoPrimitives.getIntFromByte(bucket, (int) (Math.log(bucketSize) / (Math.log(2)))))
						.size()) {
					position = position / 2;
				}

				int valueOfSubBucket = free
						.get(CryptoPrimitives.getIntFromByte(bucket, (int) (Math.log(bucketSize) / (Math.log(2)))))
						.get(position);

				free.get(CryptoPrimitives.getIntFromByte(bucket, (int) (Math.log(bucketSize) / (Math.log(2)))))
						.remove(position);

				// The last document
				if (counter == documents.size() - 1) {
					beta = 0;
				}

				byte[] label = new byte[securityParameter];
				byte[] value = new byte[valueSize];
				System.arraycopy(labelAndValue, 0, label, 0, label.length);
				System.arraycopy(labelAndValue, label.length, value, 0, value.length);

				secureIndex.get(CryptoPrimitives.getIntFromByte(bucket, (int) (Math.log(bucketSize) / (Math.log(2)))))
						.get(valueOfSubBucket).setLabel(label);

				// Computation of masked value
				Iterator<String> itr = encryptedIdToRealId.get(id).iterator();
				byte[] identifierBytes = CryptoPrimitives.encryptAES_CTR_String(keyENC,
						CryptoPrimitives.randomBytes(16), itr.next(), 60);

				byte[] identifierBF = new byte[10];
				String idBF = Integer.toString(globalCounter);

				while (idBF.length() < 10) {
					idBF = "0" + idBF;
				}

				for (int h = 0; h < 10; h++) {
					identifierBF[h] = (byte) idBF.charAt(h);
				}

				byte[] betaByte = { (byte) beta };

				byte[] concatenation = CryptoPrimitives.concat(betaByte, identifierBytes);
				concatenation = CryptoPrimitives.concat(concatenation, identifierBF);

				int k = 0;
				for (byte b : value) {
					value[k] = (byte) (b ^ concatenation[k++]);
				}
				secureIndex.get(CryptoPrimitives.getIntFromByte(bucket, (int) (Math.log(bucketSize) / (Math.log(2)))))
						.get(valueOfSubBucket).setValue(value);

				counter++;
				globalCounter++;

			}
		}

		return 1;
	}

	// ***********************************************************************************************//

	///////////////////// Setup Parallel/////////////////////////////

	// ***********************************************************************************************//

	public static void constructEMMPar(final byte[] key1, final byte[] key2, final byte[] keyENC,
			final Multimap<String, String> lookup, final Multimap<String, String> encryptedIdToRealId)
			throws InterruptedException, ExecutionException, IOException {

		// Instantiation of B buckets in the secure inverted index
		// Initialize of the free set

		// Determination of the bucketSize B
		bucketSize = lookup.size() * spaceOverhead;
		int count = 2;
		for (int j = 1; j < 1000; j++) {
			if (bucketSize > Math.pow(2, count)) {
				count = 2 * j;
			} else {
				break;
			}
		}

		bucketSize = (int) Math.pow(2, count);

		for (int i = 0; i < bucketSize; i++) {
			secureIndex.add(new ArrayList<Record>());
			free.add(new ArrayList<Integer>());
			// For each bucket initialize to S sub-buckets
			for (int j = 0; j < subBucketSize; j++) {
				// initialize all buckets with random values
				secureIndex.get(i).add(new Record(new byte[16], new byte[16]));
				free.get(i).add(j);
			}
		}

		List<String> listOfKeyword = new ArrayList<String>(lookup.keySet());
		int threads = 0;
		if (Runtime.getRuntime().availableProcessors() > listOfKeyword.size()) {
			threads = listOfKeyword.size();
		} else {
			threads = Runtime.getRuntime().availableProcessors();
		}

		ExecutorService service = Executors.newFixedThreadPool(threads);
		ArrayList<String[]> inputs = new ArrayList<String[]>(threads);

		for (int i = 0; i < threads; i++) {
			String[] tmp;
			if (i == threads - 1) {
				tmp = new String[listOfKeyword.size() / threads + listOfKeyword.size() % threads];
				for (int j = 0; j < listOfKeyword.size() / threads + listOfKeyword.size() % threads; j++) {
					tmp[j] = listOfKeyword.get((listOfKeyword.size() / threads) * i + j);
				}
			} else {
				tmp = new String[listOfKeyword.size() / threads];
				for (int j = 0; j < listOfKeyword.size() / threads; j++) {

					tmp[j] = listOfKeyword.get((listOfKeyword.size() / threads) * i + j);
				}
			}
			inputs.add(i, tmp);
		}

		List<Future<Integer>> futures = new ArrayList<Future<Integer>>();
		for (final String[] input : inputs) {
			Callable<Integer> callable = new Callable<Integer>() {
				public Integer call() throws Exception {

					int output = setup(key1, key2, keyENC, input, lookup, encryptedIdToRealId);
					return 1;
				}
			};
			futures.add(service.submit(callable));
		}

		service.shutdown();

	}

	// ***********************************************************************************************//

	///////////////////// Search Token Generation /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] token(byte[] key, String keyword) throws UnsupportedEncodingException {
		byte[] result = CryptoPrimitives.generateCmac(key, keyword);
		return result;
	}

	// ***********************************************************************************************//

	///////////////////// Query without partitioning
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static List<TSetResultFormat> query(byte[] token1, byte[] token2, List<List<Record>> secureIndex,
			int bucketSize) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {
		List<TSetResultFormat> result = new ArrayList<TSetResultFormat>();

		// initialize beta to 1
		int beta = 1;

		// initialize the counter to 0

		int counter = 0;

		int numberOfBytes = (int) Math.ceil((Math.log(bucketSize) / (Math.log(2) * 8)));

		// security parameter in bytes defines the label while the value size
		// defines the concatenation of the beta, the identifier of the document
		// and the pointer to the bloom filter

		int securityParameter = 16;
		int valueSize = 87;

		while (beta != 0) {
			// Generate the HMAC based for each identifier
			byte[] hmac = CryptoPrimitives.concat(
					CryptoPrimitives.generateHmac512(keyHMACSI,
							Integer.toString(CryptoPrimitives.getIntFromByte(
									CryptoPrimitives.generateCmac(token1, Integer.toString(counter)), 128))),
					CryptoPrimitives.generateHmac512(keyHMACSI, Integer.toString(CryptoPrimitives
							.getIntFromByte(CryptoPrimitives.generateCmac(token2, Integer.toString(counter)), 128))));

			// parsing the result of the random
			byte[] bucket = new byte[numberOfBytes];
			byte[] label = new byte[securityParameter];
			byte[] value = new byte[valueSize];

			System.arraycopy(hmac, 0, bucket, 0, bucket.length);
			System.arraycopy(hmac, bucket.length, label, 0, label.length);
			System.arraycopy(hmac, bucket.length + label.length, value, 0, value.length);

			int counterWorNotExist = 0;

			boolean flag2 = false;
			for (Record record : secureIndex
					.get(CryptoPrimitives.getIntFromByte(bucket, (int) (Math.log(bucketSize) / (Math.log(2)))))) {

				if (Arrays.equals(record.getLabel(), label)) {

					flag2 = true;
					// De-masking the value

					int k = 0;
					for (byte b : value) {
						value[k] = (byte) (b ^ record.getValue()[k++]);
					}

					// Spliting the array "value" to FLAG + TITLE + BF
					// IDENTIFIER
					byte[] flagByte = new byte[1];
					byte[] docId = new byte[76];
					byte[] bFId = new byte[10];

					System.arraycopy(value, 0, flagByte, 0, flagByte.length);
					System.arraycopy(value, flagByte.length, docId, 0, docId.length);
					System.arraycopy(value, flagByte.length + docId.length, bFId, 0, bFId.length);

					// instantiation of the record encoding
					String valueMatch = "";

					for (int s = 0; s < value.length; s++) {
						valueMatch = valueMatch + (char) value[s];
					}

					// checking if it is the last identifier
					if (String.valueOf(flagByte[0]).charAt(0) == '0') {
						beta = 0;
					}

					// return the string of the identifier and the bloom filter

					result.add(new TSetResultFormat(docId, bFId));

				} else if ((counterWorNotExist == secureIndex
						.get(CryptoPrimitives.getIntFromByte(bucket, (int) (Math.log(bucketSize) / (Math.log(2)))))
						.size() - 1) && (flag2 == false)) {
					// the word searched for does not exists
					beta = 0;
				}

				counterWorNotExist++;

			}

			counter++;
		}

		return result;
	}

}
