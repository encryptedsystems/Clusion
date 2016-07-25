//***********************************************************************************************//

// This file contains the step-by-step local benchmarking of the IEX-ZMF. The encrypted data structure remains in the RAM.
// This file also gathers stats useful to give some insights about the scheme implementation
// One needs to wait until the complete creation of the encrypted data structures of IEX-ZMF in order to issue Boolean queries.
// Queries need to be in the form of CNF. Follow on-line instructions.
//***********************************************************************************************//
package org.crypto.sse;


import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

import com.carrotsearch.sizeof.*;

public class TestLocalIEXZMF {
	private static final int falsePosRate	=	25;
	private static final int maxLengthOfMask	=	20;


	public static void main(String[] args) throws Exception{

		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		System.out.println("Enter your password :");

		String pass	=	keyRead.readLine();		

		List<byte[]> listSK	=	IEXZMF.keyGen(256, pass, "salt/salt", 100);

		long startTime =System.nanoTime();

		System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

		String pathName	=	keyRead.readLine();


		TextProc.TextProc(false, pathName);


		long startTime2 =System.nanoTime();
		System.out.println("Number of keywords pairs (w. id): "+ TextExtractPar.lp1.size());
		System.out.println("Number of keywords "+ TextExtractPar.lp1.keySet().size());

		IEXZMF.constructBFPar(new ArrayList(TextExtractPar.lp1.keySet()),listSK.get(0), listSK.get(1), maxLengthOfMask, falsePosRate);

		// Encryption of files and update the encrypted identifiers in the second lookup

		int counterFile	=	0;	
		ArrayList<File> listOfFile	=	new ArrayList<File>();

		TextProc.listf("Input", listOfFile); 
		Multimap<String, String> encryptedIdToRealId	=	ArrayListMultimap.create();

		for (File file :listOfFile){		
			encryptedIdToRealId.put(file.getName(), Integer.toString(counterFile));
			counterFile++;
		}

		// Replace all documents identifiers with a random ID

		System.out.println("\n Beginning of global encrypted multi-map construction \n");

		int bigBlock	=	1000;
		int smallBlock	=	100;
		int dataSize	=	10000;

		MMGlobal[]	localMultiMap	=	null;
		Multimap<String, Integer>	dictionaryForMM	=	null;
		//Construction by Cash et al NDSS 2014

		IEX2Lev disj	=	new IEX2Lev(MMGlobal.constructEMMPar(listSK.get(1), TextExtractPar.lp1, bigBlock, smallBlock, dataSize), localMultiMap, dictionaryForMM);

		// The line below creates a Global multi-map based on the TSet by Cash et al. Crypto'13. It is commented as we have implemented a faster instantiation of encrypted multi-map based 
		// on the construction by Cash et al. NDSS'14

		//InvertedIndex.constructEMMPar(listSK.get(1), listSK.get(2), listSK.get(3), TextExtractPar.lp1, encryptedIdToRealId);	

		long endTime2   = System.nanoTime();
		long totalTime2 = endTime2 - startTime2;

		System.out.println("\n*****************************************************************");
		System.out.println("\n\t\tSTATS");
		System.out.println("\n*****************************************************************");

		System.out.println("\nTotal Time elapsed for the entire construction in seconds: "+totalTime2/1000000000);

		// The two commented commands are used to compute the size of the encrypted Local multi-maps and global multi-maps

		//System.out.println("\nSize of the Structure EMM: "+ SizeOf.humanReadable(SizeOf.deepSizeOf(IEXZMF.bloomFilterList)));
		//System.out.println("\nSize of the Structure MMg: "+ SizeOf.humanReadable(SizeOf.deepSizeOf(disj.getGlobalMM())));
		while(true){

			// Boolean queries

			System.out.println("How many disjunctions? ");
			int numDisjunctions = Integer.parseInt(keyRead.readLine());

			// Storing the CNF form 
			String[][] bool = new String[numDisjunctions][];
			for (int i=0; i<numDisjunctions; i++){
				System.out.println("Enter the keywords of the disjunctions ");
				bool[i]	=	keyRead.readLine().split(" ");
			}

			// Generate the IEX token
			List<String> searchBol	=	new ArrayList<String>();
			for (int i=0; i<bool[0].length; i++){
				searchBol.add(bool[0][i]);
			}


			long startTime3 =System.nanoTime();

			List<Token> tokenBol	=	IEXZMF.genToken(listSK, searchBol, falsePosRate, maxLengthOfMask);
			List<String> tmpBol = IEXZMF.testLocal(tokenBol, disj, InvertedIndex.bucketSize, falsePosRate);
			System.out.println(tmpBol);

			for (int i=1; i<numDisjunctions; i++ ){
				for (int k=0; k<bool[0].length;k++){
					List<String> searchTMP	=	new ArrayList<String>();
					List<String> tmpList	=	new ArrayList<String>();
					searchTMP.add(bool[0][k]);
					for (int r=0; r< bool[i].length; r++){
						searchTMP.add(bool[i][r]);
					}

					List<Token> tokenTMP	=	IEXZMF.genToken(listSK, searchTMP, falsePosRate, maxLengthOfMask);

					// Here we perform an intersection (contrary to its argument)

					List<String>	resultTMP	=	MMGlobal.testSI(tokenTMP.get(0).getTokenMMGlobal(), disj.getGlobalMM().getDictionary(), disj.getGlobalMM().getArray());

					List<boolean[]> listOfbloomFilter	=	new ArrayList<boolean[]>();


					List<String> bFIDPaddeds	=	IEXZMF.bloomFilterStart.get(new String(tokenTMP.get(0).getTokenSI1()));

					for (int j=0; j<resultTMP.size(); j++){
						int bFID = Integer.parseInt(bFIDPaddeds.get(j));
						listOfbloomFilter.add(IEXZMF.bloomFilterMap.get(Integer.toString(bFID)).getSecureSetM());		
					}

					for (int j=0; j<resultTMP.size(); j++){

						boolean flag	=	true;

						int counter =0;
						while (flag){

							if (SecureSetM.testSM(listOfbloomFilter, tokenTMP.get(0).getTokenSM().get(counter), falsePosRate)[j]	== true){
								flag = false;
							}
							else if (counter == tokenTMP.get(0).getTokenSM().size()-1){
								break;
							}
							counter++;
						}

						if (flag == false){
							tmpList.add(resultTMP.get(j));

						}

					}

					tmpBol.retainAll(tmpList);
				}
				System.out.println("Result "+tmpBol);
			}

			long endTime3   = System.nanoTime();
			long totalTime3 = endTime3 - startTime3;

			System.out.println("\nTime elapsed for the query in ns: "+totalTime3);
		}

	}
}
