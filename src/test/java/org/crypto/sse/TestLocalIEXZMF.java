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

// This file contains the step-by-step local benchmarking of the IEX-ZMF. The encrypted data structure remains in the RAM.
// This file also gathers stats useful to give some insights about the scheme implementation
// One needs to wait until the complete creation of the encrypted data structures of IEX-ZMF in order to issue Boolean queries.
// Queries need to be in the form of CNF. Follow on-line instructions.
//***********************************************************************************************//
package org.crypto.sse;

import com.google.common.collect.Multimap;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.NoSuchPaddingException;

public class TestLocalIEXZMF {
	private static final int falsePosRate = 25;
	private static final int maxLengthOfMask = 20;

	public static void main(String[] args) throws Exception {
		
		Printer.addPrinter(new Printer(Printer.LEVEL.EXTRA));

		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		Printer.normalln("Enter your password :");

		String pass = keyRead.readLine();

		List<byte[]> listSK = IEXZMF.keyGen(128, pass, "salt/salt", 100);

		long startTime = System.nanoTime();
		
		Printer.normalln("Enter the relative path name of the folder that contains the files to make searchable");

		String pathName = keyRead.readLine();

		TextProc.TextProc(false, pathName);

		long startTime2 = System.nanoTime();
		Printer.debugln("Number of keywords pairs (w. id): " + TextExtractPar.lp1.size());
		Printer.debugln("Number of keywords " + TextExtractPar.lp1.keySet().size());

		Printer.debugln("\n Beginning of global encrypted multi-map construction \n");

		int bigBlock = 1000;
		int smallBlock = 100;
		int dataSize = 0;

		RR2Lev[] localMultiMap = null;
		Multimap<String, Integer> dictionaryForMM = null;
		// Construction by Cash et al NDSS 2014

		for (String keyword : TextExtractPar.lp1.keySet()) {

			if (dataSize < TextExtractPar.lp1.get(keyword).size()) {
				dataSize = TextExtractPar.lp1.get(keyword).size();
			}

		}

		IEX2Lev disj = new IEX2Lev(
				RR2Lev.constructEMMParGMM(listSK.get(1), TextExtractPar.lp1, bigBlock, smallBlock, dataSize),
				localMultiMap, dictionaryForMM);

		Printer.debugln("\n Beginning of local encrypted multi-map construction \n");

		IEXZMF.constructMatryoshkaPar(new ArrayList(TextExtractPar.lp1.keySet()), listSK.get(0), listSK.get(1),
				maxLengthOfMask, falsePosRate);

		long endTime2 = System.nanoTime();
		
		long totalTime2 = endTime2 - startTime2;
		Printer.statsln("\n*****************************************************************");
		Printer.statsln("\n\t\tSTATS");
		Printer.statsln("\n*****************************************************************");

		Printer.statsln(
				"\nTotal Time elapsed for the local multi-map construction in seconds: " + totalTime2 / 1000000);

		// Beginning of search phase

		while (true) {

			Printer.normalln("How many disjunctions? ");
			int numDisjunctions = Integer.parseInt(keyRead.readLine());

			// Storing the CNF form
			String[][] bool = new String[numDisjunctions][];
			for (int i = 0; i < numDisjunctions; i++) {
				Printer.normalln("Enter the keywords of the " + i + "th disjunctions ");
				bool[i] = keyRead.readLine().split(" ");
			}

			test("logZMF.txt", "Test", 1, disj, listSK, bool);
		}
	}

	public static void test(String output, String word, int numberIterations, IEX2Lev disj, List<byte[]> listSK,
			String[][] bool) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, UnsupportedEncodingException, IOException {

		long minimum = (long) Math.pow(10, 10);
		long maximum = 0;
		long average = 0;

		// Generate the IEX token
		List<String> searchBol = new ArrayList<String>();
		for (int i = 0; i < bool[0].length; i++) {
			searchBol.add(bool[0][i]);
		}

		for (int g = 0; g < numberIterations; g++) {

			long startTime3 = System.nanoTime();

			List<Token> tokenBol = IEXZMF.token(listSK, searchBol, falsePosRate, maxLengthOfMask);
			List<String> tmpBol = IEXZMF.query(tokenBol, disj, TSet.bucketSize, falsePosRate);

			for (int i = 1; i < bool.length; i++) {
				List<String> tmpBol2 = new ArrayList<String>();

				for (int k = 0; k < bool[0].length; k++) {
					List<String> searchTMP = new ArrayList<String>();
					List<String> tmpList = new ArrayList<String>();
					searchTMP.add(bool[0][k]);
					for (int r = 0; r < bool[i].length; r++) {
						searchTMP.add(bool[i][r]);
					}

					List<Token> tokenTMP = IEXZMF.token(listSK, searchTMP, falsePosRate, maxLengthOfMask);

					// Here we perform an intersection (contrary to its
					// argument)

					List<String> resultTMP = RR2Lev.query(tokenTMP.get(0).getTokenMMGlobal(),
							disj.getGlobalMM().getDictionary(), disj.getGlobalMM().getArray());

					Map<String, boolean[]> listOfbloomFilter = new HashMap<String, boolean[]>();

					List<Integer> bFIDPaddeds = IEXZMF.bloomFilterStart.get(new String(tokenTMP.get(0).getTokenSI1()));

					if (!(bFIDPaddeds == null)) {
						for (int j = 0; j < bFIDPaddeds.size(); j++) {
							int bFID = bFIDPaddeds.get(j);
							listOfbloomFilter.put(IEXZMF.bloomFilterID.get(bFID),
									IEXZMF.bloomFilterMap.get(Integer.toString(bFID)).getSecureSetM());
						}
					}

					Map<Integer, boolean[]> tempBF = new HashMap<Integer, boolean[]>();

					for (int v = 0; v < tokenTMP.get(0).getTokenSM().size(); v++) {
						tempBF.put(v,
								ZMF.testSMV2(listOfbloomFilter, tokenTMP.get(0).getTokenSM().get(v), falsePosRate));
					}

					if (!(bFIDPaddeds == null)) {
						for (int j = 0; j < bFIDPaddeds.size(); j++) {

							boolean flag = true;

							int counter = 0;
							while (flag) {

								if (tempBF.get(counter)[j] == true) {
									flag = false;
								} else if (counter == tokenTMP.get(0).getTokenSM().size() - 1) {
									break;
								}
								counter++;
							}

							if (flag == false) {
								tmpList.add(IEXZMF.bloomFilterID.get(bFIDPaddeds.get(j)));

							}

						}
					}

					tmpBol2.addAll(tmpList);

				}

				tmpBol.retainAll(tmpBol2);

			}

			Printer.normalln("Result " + tmpBol);

			long endTime3 = System.nanoTime();
			long totalTime3 = endTime3 - startTime3;

			if (totalTime3 < minimum) {

				minimum = totalTime3;

			}

			if (totalTime3 > maximum) {

				maximum = totalTime3;

			}

			average = average + totalTime3;

		}

		BufferedWriter writer2 = new BufferedWriter(new FileWriter(output, true));
		writer2.write("\n Word " + word + " minimum " + minimum);
		writer2.write("\n Word " + word + " maximum " + maximum);
		writer2.write("\n Word " + word + " average " + average / numberIterations + "\n\n");
		writer2.close();

	}

}
