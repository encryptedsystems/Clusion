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

// This file contains IEX-ZMF implementation. KeyGen, Setup, Token and Test algorithms. 
// We also propose an implementation of a possible filtering mechanism that reduces the storage overhead. 

//***********************************************************************************************//	

//This Class is associated to the first version of multi-map encryption scheme (in the OXT paper) where the BF ids are stored in the EMM itself. This class needs to be
//modified in such a way that the BF are not in the EMM
//In order to use this class the documents identifiers have to be encrypted before being fed to the scheme

package org.crypto.sse;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.*;

public class IEXZMF implements Serializable {

	public static int numberOfBF = 0;
	public static int numberOfkeywordsProcessed = 0;
	public static double filterParameter = 0.2;

	public static List<ZMFFormat> bloomFilterList = new ArrayList<ZMFFormat>();
	public static HashMap<String, ZMFFormat> bloomFilterMap = new HashMap<String, ZMFFormat>();
	public static HashMap<String, List<Integer>> bloomFilterStart = new HashMap<String, List<Integer>>();
	public static HashMap<Integer, String> bloomFilterID = new HashMap<Integer, String>();

	// ***********************************************************************************************//

	///////////////////// KeyGen /////////////////////////////

	// ***********************************************************************************************//

	public static List<byte[]> keyGen(int keySize, String password, String filePathString, int icount)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

		List<byte[]> listOfkeys = new ArrayList<byte[]>();

		// Generation of the key for Secure Set membership
		listOfkeys.add(ZMF.keyGenSM(keySize * 3, password + "setM", filePathString, icount));

		// Generation of two keys for Secure inverted index
		listOfkeys.add(TSet.keyGen(keySize, password + "secureIndex1", filePathString, icount));
		listOfkeys.add(TSet.keyGen(keySize, password + "secureIndex2", filePathString, icount));

		// Generation of one key for encryption
		listOfkeys.add(ZMF.keyGenSM(keySize, password + "encryption", filePathString, icount));

		return listOfkeys;

	}

	// ***********************************************************************************************//

	///////////////////// Setup /////////////////////////////

	// ***********************************************************************************************//

	public static void setup(ObjectOutputStream output, List<byte[]> listOfkeys, String pwd, int maxLengthOfMask,
			int falsePosRate) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, IOException, InterruptedException,
			ExecutionException {

		TextProc.TextProc(false, pwd);

		System.out.println("\n Beginning of ZMF construction \n");

		System.out.println("Number of extracted keywords " + TextExtractPar.lp1.keySet().size());
		System.out.println("Size of the inverted index (leakage N) " + TextExtractPar.lp1.size());

		constructMatryoshkaPar(new ArrayList(TextExtractPar.lp1.keySet()), listOfkeys.get(0), listOfkeys.get(1),
				maxLengthOfMask, falsePosRate);

	}

	// ***********************************************************************************************//

	///////////////////// GenToken /////////////////////////////

	// ***********************************************************************************************/

	public static List<Token> token(List<byte[]> listOfkeys, List<String> search, int falsePosRate, int maxLengthOfMask)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			IOException {
		List<Token> token = new ArrayList<Token>();

		for (int i = 0; i < search.size(); i++) {

			List<String> subSearch = new ArrayList<String>();
			// Create a temporary list that carry keywords in *order*
			for (int j = i; j < search.size(); j++) {
				subSearch.add(search.get(j));
			}

			token.add(new Token(subSearch, listOfkeys, maxLengthOfMask, falsePosRate));
		}
		return token;

	}

	// ***********************************************************************************************//

	///////////////////// Query Algorithm /////////////////////////////

	// ***********************************************************************************************/

	public static List<String> query(List<Token> token, IEX2Lev disj, int bucketSize, int falsePosRate)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {
		List<String> result = new ArrayList<String>();

		for (int i = 0; i < token.size(); i++) {
			List<String> resultTMP = RR2Lev.query(token.get(i).getTokenMMGlobal(), disj.getGlobalMM().getDictionary(),
					disj.getGlobalMM().getArray());

			// System.out.println("Result of MM Global "+resultTMP);

			Map<String, boolean[]> listOfbloomFilter = new HashMap<String, boolean[]>();

			List<Integer> bFIDPaddeds = new ArrayList<Integer>();

			bFIDPaddeds = bloomFilterStart.get(new String(token.get(i).getTokenSI1()));

			if ((i < token.size() - 1) && !(bFIDPaddeds == null)) {
				// System.out.println("bFIDPaddeds "+bFIDPaddeds);

				for (int j = 0; j < bFIDPaddeds.size(); j++) {

					// Decode first the BF identifier

					int bFID = bFIDPaddeds.get(j);
					// endOf decoding the BF id

					// Checking all corresponding tokenSM against the bloom
					// filter

					listOfbloomFilter.put(bloomFilterID.get(bFID),
							bloomFilterMap.get(Integer.toString(bFID)).getSecureSetM());

				}

			}

			Map<Integer, boolean[]> tempBF = new HashMap<Integer, boolean[]>();

			if (i < token.size() - 1) {
				for (int v = 0; v < token.get(i).getTokenSM().size(); v++) {
					tempBF.put(v, ZMF.testSMV2(listOfbloomFilter, token.get(i).getTokenSM().get(v), falsePosRate));
				}
			}
			if (i < token.size() - 1) {

				if (!(bFIDPaddeds == null)) {
					for (int j = 0; j < bFIDPaddeds.size(); j++) {

						boolean flag = true;

						int counter = 0;
						while (flag) {

							if (tempBF.get(counter)[j] == true) {
								flag = false;
							} else if (counter == token.get(i).getTokenSM().size() - 1) {
								break;
							}
							counter++;
						}

						// due to filtering replace resultTMP by the following:

						if (flag == true) {
							result.add(IEXZMF.bloomFilterID.get(bFIDPaddeds.get(j)));

						}
					}

				}

			} else {
				result.addAll(resultTMP);
			}

		}

		return result;

	}
	// ***********************************************************************************************//

	///////////////////// Decryption of identifiers Client side
	///////////////////// ///////////////////// /////////////////////////////

	// ***********************************************************************************************/

	public static List<String> decryptMatch(List<byte[]> encryptedID, byte[] keyENC)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {
		List<String> result = new ArrayList<String>();

		for (int i = 0; i < encryptedID.size(); i++) {
			String tmp = new String(CryptoPrimitives.decryptAES_CTR_String(encryptedID.get(i), keyENC))
					.split("\t\t\t")[0];
			result.add(tmp);
		}

		return result;
	}

	public static void constructMatryoshkaPar(List<String> listOfKeyword, final byte[] keySM, final byte[] keyInvInd,
			final int maxLengthOfMask, final int falsePosRate)
			throws InterruptedException, ExecutionException, IOException {

		long startTime = System.nanoTime();

		int threads = 0;
		if (Runtime.getRuntime().availableProcessors() > listOfKeyword.size()) {
			threads = listOfKeyword.size();
		} else {
			threads = Runtime.getRuntime().availableProcessors();
		}

		System.out.println("Number of threads " + threads);

		ExecutorService service = Executors.newFixedThreadPool(threads);

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
							bloomFilterList
									.addAll(secureSetMPar(input, keySM, keyInvInd, maxLengthOfMask, falsePosRate));
						} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException
								| NoSuchPaddingException | IOException e) {
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

		long endTime = System.nanoTime();
		long totalTime = endTime - startTime;
		System.out.println(
				"\nTime in (ns) for one Matryoshka filter in average: " + totalTime / TextExtractPar.lp1.size());
		System.out.println("\nTime to construct local multi-maps in ms " + totalTime / 1000000);

	}

	public static List<ZMFFormat> secureSetMPar(String[] input, byte[] keySM, byte[] keyInvInd, int maxLengthOfMask,
			int falsePosRate) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, IOException {
		List<ZMFFormat> result = new ArrayList<ZMFFormat>();

		for (String keyword : input) {

			// First step of filtering where we reduce all BFs that do not
			// verify the threshold

			System.out.println("\n \n Number of keywords processed % "
					+ (numberOfkeywordsProcessed * 100) / TextExtractPar.lp1.keySet().size() + "\n");

			System.out.println("keyword being processed to issue matryoshka filters: " + keyword);

			Map<String, boolean[]> secureSetM2 = ZMF.setupSetMV2(keySM, keyword, TextExtractPar.lp2, TextExtractPar.lp1,
					falsePosRate);
			int counter = 0;
			for (String id : secureSetM2.keySet()) {
				result.add(new ZMFFormat(secureSetM2.get(id), Integer.toString(numberOfBF)));

				bloomFilterMap.put(Integer.toString(numberOfBF),
						new ZMFFormat(secureSetM2.get(id), Integer.toString(numberOfBF)));
				if (counter == 0) {
					bloomFilterStart.put(new String(TSet.token(keyInvInd, keyword)), new ArrayList<Integer>());
					bloomFilterStart.get(new String(TSet.token(keyInvInd, keyword))).add(numberOfBF);
				} else {
					bloomFilterStart.get(new String(TSet.token(keyInvInd, keyword))).add(numberOfBF);
				}

				bloomFilterID.put(numberOfBF, id);

				System.out.println("Matryoshka filter number: " + numberOfBF);
				numberOfBF++;
				counter++;

			}
		}

		numberOfkeywordsProcessed++;

		return result;
	}

}
