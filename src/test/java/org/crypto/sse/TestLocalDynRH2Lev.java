//***********************************************************************************************//
// This file is to test the 2Lev construction by Cash et al. NDSS'14. 
//**********************************************************************************************

package org.crypto.sse;

import java.io.*;
import java.util.ArrayList;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.TreeMultimap;

public class TestLocalDynRH2Lev {

	public static void main(String[] args) throws Exception {
		
		Printer.addPrinter(new Printer(Printer.LEVEL.EXTRA));

		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		System.out.println("Enter your password :");

		String pass = keyRead.readLine();

		byte[] sk = RR2Lev.keyGen(256, pass, "salt/salt", 100000);

		System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

		String pathName = keyRead.readLine();

		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);

		TextProc.TextProc(false, pathName);

		// The two parameters depend on the size of the dataset. Change
		// accordingly to have better search performance
		int bigBlock = 1000;
		int smallBlock = 100;
		int dataSize = 10000;

		// // Construction of the global multi-map
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");

		DynRH2Lev twolev = DynRH2Lev.constructEMMParGMM(sk, TextExtractPar.lp1, bigBlock, smallBlock, dataSize);

		// Empty the previous multimap

		TextExtractPar.lp1 = ArrayListMultimap.create();

		// Update phase

		System.out.println("Enter the relative path name of the folder that contains the files to add:");

		pathName = keyRead.readLine();

		listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);
		TextProc.TextProc(false, pathName);

		TreeMultimap<String, byte[]> tokenUp = DynRH2Lev.tokenUpdate(sk, TextExtractPar.lp1);
		DynRH2Lev.update(twolev.getDictionaryUpdates(), tokenUp);

		System.out.println("Enter 1 for forward secure search and 0 otherwise");

		pathName = keyRead.readLine();

		if (pathName.equals("1")) {

			while (true) {

				System.out.println("Enter the keyword to search for:");
				String keyword = keyRead.readLine();
				byte[][] token = DynRH2Lev.genTokenFS(sk, keyword);

				System.out.println(DynRH2Lev.resolve(CryptoPrimitives.generateCmac(sk, 3 + new String()), twolev
						.queryFS(token, twolev.getDictionary(), twolev.getArray(), twolev.getDictionaryUpdates())));

			}
		} else {
			System.out.println("Enter the keyword to search for:");
			String keyword = keyRead.readLine();
			byte[][] token = DynRH2Lev.genToken(sk, keyword);

			System.out.println(DynRH2Lev.resolve(CryptoPrimitives.generateCmac(sk, 3 + new String()),
					twolev.query(token, twolev.getDictionary(), twolev.getArray(), twolev.getDictionaryUpdates())));

		}

	}
}
