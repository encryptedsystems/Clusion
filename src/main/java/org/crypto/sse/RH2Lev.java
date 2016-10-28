//***********************************************************************************************//

/////////////////////    Implementation of 2Lev scheme of NDSS'14 

/////////////////////				Response Hiding 					///////////

//***********************************************************************************************//	

package org.crypto.sse;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.*;

public class RH2Lev {

	// define the number of character that a file identifier can have
	public static int sizeOfFileIdentifer = 100;
	public static String separator = "seperator";

	public static byte[] master = null;
	public static boolean lmm = false;
	public static String eval = "";

	public static int counter = 0;

	public Multimap<String, byte[]> dictionary = ArrayListMultimap.create();
	public static List<Integer> free = new ArrayList<Integer>();
	static byte[][] array = null;
	byte[][] arr = null;

	public RH2Lev(Multimap<String, byte[]> dictionary, byte[][] arr) {
		this.dictionary = dictionary;
		this.arr = arr;
	}

	public Multimap<String, byte[]> getDictionary() {
		return dictionary;
	}

	public void setDictionary(Multimap<String, byte[]> dictionary) {
		this.dictionary = dictionary;
	}

	public byte[][] getArray() {
		return arr;
	}

	public void setArray(byte[][] array) {
		this.arr = array;
	}

	public static RH2Lev constructEMMPar(final byte[] key, final Multimap<String, String> lookup, final int bigBlock,
			final int smallBlock, final int dataSize) throws InterruptedException, ExecutionException, IOException {

		final Multimap<String, byte[]> dictionary = ArrayListMultimap.create();

		// System.out.println("\t Initialization of free set \n");

		for (int i = 0; i < dataSize; i++) {
			// initialize all buckets with random values
			free.add(i);
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

		// System.out.println("\t Partitionning the dictionary for parallel
		// computation \n");

		final Map<Integer, String> concurrentMap = new ConcurrentHashMap<Integer, String>();
		for (int i = 0; i < listOfKeyword.size(); i++) {
			concurrentMap.put(i, listOfKeyword.get(i));
		}

		for (int j = 0; j < threads; j++) {
			service.execute(new Runnable() {
				@SuppressWarnings("unused")
				@Override
				public void run() {

					while (concurrentMap.keySet().size() > 0) {
						// write code
						Set<Integer> possibleValues = concurrentMap.keySet();

						Random rand = new Random();

						int temp = rand.nextInt(possibleValues.size());

						List<Integer> listOfPossibleKeywords = new ArrayList<Integer>(possibleValues);

						// set the input as randomly selected from the remaining
						// possible keys
						String[] input = { concurrentMap.get(listOfPossibleKeywords.get(temp)) };

						// remove the key
						concurrentMap.remove(listOfPossibleKeywords.get(temp));

						try {
							// bloomFilterList.addAll(secureSetMPar(input,keySM,
							// keyInvInd, maxLengthOfMask, falsePosRate));
							Multimap<String, byte[]> output = setupSI(key, input, lookup, bigBlock, smallBlock,
									dataSize);
							Set<String> keys = output.keySet();

							for (String k : keys) {
								dictionary.putAll(k, output.get(k));
							}
						} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException
								| NoSuchPaddingException | IOException | InvalidAlgorithmParameterException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
			});
		}

		// Make sure executor stops
		service.shutdown();

		// Blocks until all tasks have completed execution after a shutdown
		// request
		service.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);

		return new RH2Lev(dictionary, array);
	}

	public static RH2Lev constructEMMParGMM(final byte[] key, final Multimap<String, String> lookup, final int bigBlock,
			final int smallBlock, final int dataSize) throws InterruptedException, ExecutionException, IOException {

		final Multimap<String, byte[]> dictionary = ArrayListMultimap.create();

		// System.out.println("\t Initialization of free set \n");

		for (int i = 0; i < dataSize; i++) {
			// initialize all buckets with random values
			free.add(i);
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

		// System.out.println("\t Partitionning the dictionary for parallel
		// computation \n");

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

		System.out.println("\t End of Partitionning  \n");

		List<Future<Multimap<String, byte[]>>> futures = new ArrayList<Future<Multimap<String, byte[]>>>();
		for (final String[] input : inputs) {
			Callable<Multimap<String, byte[]>> callable = new Callable<Multimap<String, byte[]>>() {
				public Multimap<String, byte[]> call() throws Exception {

					Multimap<String, byte[]> output = setupSI(key, input, lookup, bigBlock, smallBlock, dataSize);
					return output;
				}
			};
			futures.add(service.submit(callable));
		}

		service.shutdown();

		for (Future<Multimap<String, byte[]>> future : futures) {
			Set<String> keys = future.get().keySet();

			for (String k : keys) {
				dictionary.putAll(k, future.get().get(k));
			}

		}

		return new RH2Lev(dictionary, array);
	}

	// ***********************************************************************************************//

	///////////////////// SetupSI /////////////////////////////

	// ***********************************************************************************************//

	public static Multimap<String, byte[]> setupSI(byte[] key, String[] listOfKeyword, Multimap<String, String> lookup,
			int bigBlock, int smallBlock, int dataSize) throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {

		// determine the size f the data set and therefore the size of the array
		array = new byte[dataSize][];
		Multimap<String, byte[]> gamma = ArrayListMultimap.create();
		long startTime = System.nanoTime();

		for (String word : listOfKeyword) {

			counter++;
			if (((float) counter / 10000) == (int) (counter / 10000)) {
				System.out.println("Counter " + counter);
			}

			// generate the tag
			// Note that to avoid key collision all words "word" need to be
			// encoded to have the same length
			byte[] key1 = CryptoPrimitives.generateCmac(key, 1 + word);
			byte[] key2 = CryptoPrimitives.generateCmac(key, 2 + word);

			// generate keys for response-hiding construction for SIV (Synthetic
			// IV)
			byte[] key3 = CryptoPrimitives.generateCmac(master, 3 + new String());

			byte[] key4 = null;
			if (lmm == false) {
				key4 = CryptoPrimitives.generateCmac(master, 4 + word);
			} else {
				key4 = CryptoPrimitives.generateCmac(master, eval);
			}

			// Encryption of the lookup DB(w) deterministically to create unique
			// tags

			List<String> encryptedID = new ArrayList<String>();

			for (String id : lookup.get(word)) {
				encryptedID
						.add(new String(CryptoPrimitives.DTE_encryptAES_CTR_String(key3, key4, id, 20), "ISO-8859-1"));
			}

			String encryptedIdString = "";

			for (String s : encryptedID) {
				encryptedIdString += s + separator;
			}

			int t = (int) Math.ceil((float) lookup.get(word).size() / bigBlock);

			if (lookup.get(word).size() <= smallBlock) {
				// pad DB(w) to "small block"
				byte[] l = CryptoPrimitives.generateCmac(key1, Integer.toString(0));

				gamma.put(new String(l), CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16),
						"1" + separator + encryptedIdString, smallBlock * sizeOfFileIdentifer));
			}

			else {

				List<String> listArrayIndex = new ArrayList<String>();

				for (int j = 0; j < t; j++) {

					List<String> encryptedID1 = new ArrayList<String>(encryptedID);

					if (j != t - 1) {

						encryptedID1 = encryptedID1.subList(j * bigBlock, (j + 1) * bigBlock);
					} else {
						int sizeList = encryptedID.size();

						encryptedID1 = encryptedID1.subList(j * bigBlock, encryptedID1.size());

						for (int s = 0; s < ((j + 1) * bigBlock - sizeList); s++) {
							encryptedID1.add(separator);
						}

					}

					encryptedIdString = "";

					for (String s : encryptedID1) {
						encryptedIdString += s + separator;
					}

					// generate the integer which is associated to free[b]

					// System.out.println("Free Size "+free.size());

					// System.out.println("Free Size details "+(int)
					// Math.ceil(((float)
					// Math.log(free.size())/(Math.log(2)*8))));

					byte[] randomBytes = CryptoPrimitives
							.randomBytes((int) Math.ceil(((float) Math.log(free.size()) / (Math.log(2) * 8))));

					int position = CryptoPrimitives.getIntFromByte(randomBytes,
							(int) Math.ceil(Math.log(free.size()) / Math.log(2)));

					while (position >= free.size() - 1) {
						position = position / 2;
					}

					int tmpPos = free.get(position);
					array[tmpPos] = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16),
							encryptedIdString, bigBlock * sizeOfFileIdentifer);
					listArrayIndex.add(tmpPos + "***");

					free.remove(position);

				}

				String listArrayIndexString = "";

				for (String s : listArrayIndex) {
					listArrayIndexString += s + separator;
				}

				// medium case
				if (t <= smallBlock) {
					byte[] l = CryptoPrimitives.generateCmac(key1, Integer.toString(0));
					gamma.put(new String(l),
							CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16),
									"2" + separator + listArrayIndexString, smallBlock * sizeOfFileIdentifer));
				}
				// big case
				else {
					int tPrime = (int) Math.ceil((float) t / bigBlock);

					List<String> listArrayIndexTwo = new ArrayList<String>();

					for (int l = 0; l < tPrime; l++) {
						List<String> tmpListTwo = new ArrayList<String>(listArrayIndex);

						if (l != tPrime - 1) {
							tmpListTwo = tmpListTwo.subList(l * bigBlock, (l + 1) * bigBlock);
						} else {

							int sizeList = tmpListTwo.size();

							tmpListTwo = tmpListTwo.subList(l * bigBlock, tmpListTwo.size());
							for (int s = 0; s < ((l + 1) * bigBlock - sizeList); s++) {
								tmpListTwo.add("***");
							}
						}

						// generate the integer which is associated to free[b]

						byte[] randomBytes = CryptoPrimitives
								.randomBytes((int) Math.ceil((Math.log(free.size()) / (Math.log(2) * 8))));

						int position = CryptoPrimitives.getIntFromByte(randomBytes,
								(int) Math.ceil(Math.log(free.size()) / Math.log(2)));

						while (position >= free.size()) {
							position = position / 2;
						}

						int tmpPos = free.get(position);

						String tmpListTwoString = "";

						for (String s : tmpListTwo) {
							tmpListTwoString += s + separator;
						}

						array[tmpPos] = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16),
								tmpListTwoString, bigBlock * sizeOfFileIdentifer);

						listArrayIndexTwo.add(tmpPos + separator);

						free.remove(position);

					}

					String listArrayIndexTwoString = "";

					for (String s : listArrayIndexTwo) {
						listArrayIndexTwoString += s + separator;
					}
					// Pad the second set of identifiers

					byte[] l = CryptoPrimitives.generateCmac(key1, Integer.toString(0));
					gamma.put(new String(l),
							CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16),
									"3" + separator + listArrayIndexTwoString, smallBlock * sizeOfFileIdentifer));

				}

			}

		}
		long endTime = System.nanoTime();
		long totalTime = endTime - startTime;
		// System.out.println("Time for one (w, id) "+totalTime/lookup.size());
		return gamma;
	}

	// ***********************************************************************************************//

	///////////////////// TestSI /////////////////////////////

	// ***********************************************************************************************//

	public static List<String> testSI(byte[][] keys, Multimap<String, byte[]> dictionary, byte[][] array)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		byte[] l = CryptoPrimitives.generateCmac(keys[0], Integer.toString(0));

		List<byte[]> tempList = new ArrayList<byte[]>(dictionary.get(new String(l)));

		if (!(tempList.size() == 0)) {
			String temp = (new String(CryptoPrimitives.decryptAES_CTR_String(tempList.get(0), keys[1])))
					.split("\t\t\t")[0];

			String[] result = temp.split(separator);

			List<String> resultFinal = new ArrayList<String>(Arrays.asList(result));
			// We remove the flag that identifies the size of the dataset

			if (result[0].equals("1")) {
				resultFinal.remove(0);
				return resultFinal;
			}

			else if (result[0].equals("2")) {

				resultFinal.remove(0);

				List<String> resultFinal2 = new ArrayList<String>();

				for (String key : resultFinal) {

					boolean flag = true;
					int counter = 0;
					while (flag) {

						if (counter < key.length() && Character.isDigit(key.charAt(counter))) {

							counter++;
						}

						else {
							flag = false;
						}
					}

					String temp2 = (new String(CryptoPrimitives.decryptAES_CTR_String(
							array[Integer.parseInt((String) key.subSequence(0, counter))], keys[1])))
									.split("\t\t\t")[0];

					String[] result3 = temp2.split(separator);

					List<String> tmp = new ArrayList<String>(Arrays.asList(result3));
					resultFinal2.addAll(tmp);
				}

				return resultFinal2;
			}

			else if (result[0].equals("3")) {

				resultFinal.remove(0);
				List<String> resultFinal2 = new ArrayList<String>();
				for (String key : resultFinal) {

					boolean flag = true;
					int counter = 0;
					while (flag) {

						if (counter < key.length() && Character.isDigit(key.charAt(counter))) {

							counter++;
						}

						else {
							flag = false;
						}
					}
					String temp2 = (new String(CryptoPrimitives.decryptAES_CTR_String(
							array[Integer.parseInt((String) key.subSequence(0, counter))], keys[1])))
									.split("\t\t\t")[0];

					String[] result3 = temp2.split(separator);
					List<String> tmp = new ArrayList<String>(Arrays.asList(result3));
					resultFinal2.addAll(tmp);
				}

				List<String> resultFinal3 = new ArrayList<String>();

				for (String key : resultFinal2) {

					boolean flag = true;
					int counter = 0;

					while (flag) {

						if (counter < key.length() && Character.isDigit(key.charAt(counter))) {

							counter++;
						}

						else {
							flag = false;
						}
					}
					if (counter == 0) {
						break;
					}

					String temp2 = (new String(CryptoPrimitives.decryptAES_CTR_String(
							array[Integer.parseInt((String) key.subSequence(0, counter))], keys[1])))
									.split("\t\t\t")[0];

					String[] result3 = temp2.split(separator);

					List<String> tmp = new ArrayList<String>(Arrays.asList(result3));

					resultFinal3.addAll(tmp);
				}

				return resultFinal3;
			}
		}
		return new ArrayList<String>();
	}

	// ***********************************************************************************************//

	///////////////////// Resolve Algorithm /////////////////////////////

	// ***********************************************************************************************//

	public static List<String> resolve(byte[] key, List<String> list)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		List<String> result = new ArrayList<String>();

		for (String id : list) {
			byte[] id2 = id.getBytes("ISO-8859-1");

			result.add(new String(CryptoPrimitives.decryptAES_CTR_String(id2, key)).split("\t\t\t")[0]);
		}

		return result;
	}

}
