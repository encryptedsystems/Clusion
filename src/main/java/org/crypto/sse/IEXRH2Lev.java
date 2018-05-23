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

// This file contains IEX-2Lev implementation for response hiding. KeyGen, Setup, Token and Query algorithms. 
// We also propose an implementation of a possible filtering mechanism that reduces the storage overhead. 

//***********************************************************************************************//	

package org.crypto.sse;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.ExecutionException;

public class IEXRH2Lev implements Serializable {

	// Parameter of Disjunctive search
	public static int maxDocumentIDs = 0;
	// Change it based on data distribution and storage restrictions
	static double filterParameter = 0;
	public static long numberPairs = 0;
	RH2Lev globalMM = null;
	RH2Lev[] localMultiMap = null;
	Multimap<String, Integer> dictionaryForMM = null;

	public IEXRH2Lev(RH2Lev globalMM, RH2Lev[] localMultiMap, Multimap<String, Integer> dictionaryForMM) {
		this.globalMM = globalMM;
		this.localMultiMap = localMultiMap;
		this.dictionaryForMM = dictionaryForMM;
	}

	public RH2Lev getGlobalMM() {
		return globalMM;
	}

	public void setGlobalMM(RH2Lev globalMM) {
		this.globalMM = globalMM;
	}

	public RH2Lev[] getLocalMultiMap() {
		return localMultiMap;
	}

	public void setLocalMultiMap(RH2Lev[] localMultiMap) {
		this.localMultiMap = localMultiMap;
	}

	public Multimap<String, Integer> getDictionaryForMM() {
		return dictionaryForMM;
	}

	public void setDictionaryForMM(Multimap<String, Integer> dictionaryForMM) {
		this.dictionaryForMM = dictionaryForMM;
	}

	// ***********************************************************************************************//

	///////////////////// Key Generation /////////////////////////////

	// ***********************************************************************************************//

	public static List<byte[]> keyGen(int keySize, String password, String filePathString, int icount)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

		List<byte[]> listOfkeys = new ArrayList<byte[]>();

		// Generation of two keys for Secure inverted index
		listOfkeys.add(TSet.keyGen(keySize, password + "secureIndex", filePathString, icount));
		listOfkeys.add(TSet.keyGen(keySize, password + "dictionary", filePathString, icount));

		// Generation of one key for encryption
		listOfkeys.add(ZMF.keyGenSM(keySize, password + "encryption", filePathString, icount));

		return listOfkeys;

	}

	// ***********************************************************************************************//

	///////////////////// Setup /////////////////////////////

	// ***********************************************************************************************//

	public static IEXRH2Lev setup(List<byte[]> keys, Multimap<String, String> lookup, Multimap<String, String> lookup2,
			int bigBlock, int smallBlock, int dataSize) throws InterruptedException, ExecutionException, IOException {

		// Instantiation of the object that contains Global MM, Local MMs and
		// the dictionary
		RH2Lev[] localMultiMap = new RH2Lev[lookup.keySet().size()];
		Multimap<String, Integer> dictionaryForMM = ArrayListMultimap.create();

		System.out.println("Number of (w, id) pairs " + lookup.size());

		System.out.println("Number of keywords " + lookup.keySet().size());

		System.out.println("Maximum size of |DB(w)| " + TextExtractPar.maxTupleSize);

		BufferedWriter writer = new BufferedWriter(new FileWriter("logs.txt", true));

		writer.write("\n *********************Stats******* \n");

		writer.write("\n Number of (w, id) pairs " + lookup2.size());
		writer.write("\n Number of keywords " + lookup.keySet().size());

		int counter = 0;

		///////////////////// Computing Filtering Factor and exact needed data
		///////////////////// size/////////////////////////////

		HashMap<Integer, Integer> histogram = new HashMap<Integer, Integer>();
		System.out.println("Number of documents " + lookup2.keySet().size());
		for (String keyword : lookup.keySet()) {
			if (histogram.get(lookup.get(keyword).size()) != null) {
				int tmp = histogram.get(lookup.get(keyword).size());
				histogram.put(lookup.get(keyword).size(), tmp + 1);
			} else {
				histogram.put(lookup.get(keyword).size(), 1);
			}

			if (dataSize < lookup.get(keyword).size()) {
				dataSize = lookup.get(keyword).size();
			}

		}

		// Construction of the global multi-map
		System.out.println("\nBeginning of Global MM creation \n");

		long startTime1 = System.nanoTime();

		IEXRH2Lev disj2 = new IEXRH2Lev(RH2Lev.constructEMMParGMM(keys.get(0), lookup, bigBlock, smallBlock, dataSize),
				localMultiMap, dictionaryForMM);

		long endTime1 = System.nanoTime();

		writer.write("\n Time of MM global setup time #(w, id)/#DB " + (endTime1 - startTime1) / lookup2.size());
		writer.close();

		numberPairs = numberPairs + lookup.size();

		// Construction of the local multi-map

		System.out.println("Start of Local Multi-Map construction");

		long startTime = System.nanoTime();

		for (String keyword : lookup.keySet()) {

			// Stats for keeping track with the evaluation

			for (int j = 0; j < 100; j++) {

				if (counter == (int) ((j + 1) * lookup.keySet().size() / 100)) {
					BufferedWriter writer2 = new BufferedWriter(new FileWriter("temp-logs.txt", true));
					writer2.write("\n Number of local multi-maps created" + j + " %");
					writer2.close();

					break;
				}
			}

			// Filter setting optional. For a setup without any filtering set
			// filterParameter to 0
			if (((double) lookup.get(keyword).size() / TextExtractPar.maxTupleSize > filterParameter)) {

				// Stats
				System.out.println("Keyword in LMM " + keyword);
				BufferedWriter writer3 = new BufferedWriter(new FileWriter("words-logs.txt", true));
				writer3.write("\n Keyword in LMM " + keyword);
				writer3.close();

				for (int j = 0; j < 10; j++) {

					if (counter == (int) ((j + 1) * lookup.keySet().size() / 10)) {
						System.out.println("Number of total keywords processed equals " + j + "0 % \n");
						break;
					}
				}

				// First computing V_w. Determine Doc identifiers

				Set<String> VW = new TreeSet<String>();
				for (String idDoc : lookup.get(keyword)) {
					VW.addAll(lookup2.get(idDoc));
				}

				Multimap<String, String> secondaryLookup = ArrayListMultimap.create();

				// here we are only interested in documents in the intersection
				// between "keyword" and "word"
				for (String word : VW) {
					// Filter setting optional. For a setup without any
					// filtering set filterParameter to 0
					if (((double) lookup.get(word).size() / TextExtractPar.maxTupleSize > filterParameter)) {
						Collection<String> l1 = new ArrayList<String>(lookup.get(word));
						Collection<String> l2 = new ArrayList<String>(lookup.get(keyword));
						l1.retainAll(l2);
						secondaryLookup.putAll(word, l1);
					}
				}

				// End of VW construction
				RH2Lev.counter = 0;

				// dataSize = (int) filterParameter;
				EMM2Lev.eval = 4 + keyword;
				EMM2Lev.lmm = true;

				disj2.getLocalMultiMap()[counter] = RH2Lev.constructEMMParGMM(
						CryptoPrimitives.generateCmac(keys.get(0), keyword), secondaryLookup, bigBlock, smallBlock,
						dataSize);
				byte[] key3 = CryptoPrimitives.generateCmac(keys.get(1), 3 + keyword);
				numberPairs = numberPairs + secondaryLookup.size();
				dictionaryForMM.put(new String(key3), counter);

			}
			counter++;

		}

		long endTime = System.nanoTime();

		System.out.println("Time to construct LMM " + (endTime - startTime) / 1000000000);

		disj2.setDictionaryForMM(dictionaryForMM);
		return disj2;

	}

	// ***********************************************************************************************//

	///////////////////// Search Token Generation /////////////////////////////

	// ***********************************************************************************************//

	public static List<TokenDIS> token(List<byte[]> listOfkeys, List<String> search)
			throws UnsupportedEncodingException {
		List<TokenDIS> token = new ArrayList<TokenDIS>();

		for (int i = 0; i < search.size(); i++) {

			List<String> subSearch = new ArrayList<String>();
			// Create a temporary list that carry keywords in *order*
			for (int j = i; j < search.size(); j++) {
				subSearch.add(search.get(j));
			}

			token.add(new TokenDIS(subSearch, listOfkeys));
		}
		return token;

	}

	// ***********************************************************************************************//

	///////////////////// Query Algorithm /////////////////////////////

	// ***********************************************************************************************//

	public static Set<String> query(List<TokenDIS> token, IEXRH2Lev disj)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		Set<String> finalResult = new TreeSet<String>();
		for (int i = 0; i < token.size(); i++) {

			Set<String> result = new HashSet<String>(RH2Lev.query(token.get(i).getTokenMMGlobal(),
					disj.getGlobalMM().getDictionary(), disj.getGlobalMM().getArray()));

			if (!(result.size() == 0)) {
				List<Integer> temp = new ArrayList<Integer>(
						disj.getDictionaryForMM().get(new String(token.get(i).getTokenDIC())));

				if (!(temp.size() == 0)) {
					int pos = temp.get(0);

					for (int j = 0; j < token.get(i).getTokenMMLocal().size(); j++) {

						Set<String> temporary = new HashSet<String>();
						List<String> tempoList = RH2Lev.query(token.get(i).getTokenMMLocal().get(j),
								disj.getLocalMultiMap()[pos].getDictionary(), disj.getLocalMultiMap()[pos].getArray());

						if (!(tempoList == null)) {
							temporary = new HashSet<String>(RH2Lev.query(token.get(i).getTokenMMLocal().get(j),
									disj.getLocalMultiMap()[pos].getDictionary(),
									disj.getLocalMultiMap()[pos].getArray()));
						}

						result = Sets.difference(result, temporary);
						if (result.isEmpty()) {
							break;
						}

					}
				}
				finalResult.addAll(result);
			}
		}

		return finalResult;

	}

}
