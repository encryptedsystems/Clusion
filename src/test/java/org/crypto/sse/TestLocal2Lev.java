//***********************************************************************************************//
// This file is to test the 2Lev construction by Cash et al. NDSS'14. 
//**********************************************************************************************

package org.crypto.sse;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class TestLocal2Lev {

	public static void main(String[] args) throws Exception {

		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		System.out.println("Enter your password :");

		String pass = keyRead.readLine();

		List<byte[]> listSK = IEX2Lev.keyGen(256, pass, "salt/salt", 100);

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

		// Construction of the global multi-map
		System.out.println("\nBeginning of Global MM creation \n");

		MMGlobal twolev = MMGlobal.constructEMMParGMM(listSK.get(0), TextExtractPar.lp1, bigBlock, smallBlock,
				dataSize);

		while (true) {

			System.out.println("Enter the keyword to search for:");
			String keyword = keyRead.readLine();
			byte[][] token = MMGlobal.genToken(listSK.get(0), keyword);

			System.out.println("Final Result: " + twolev.testSI(token, twolev.getDictionary(), twolev.getArray()));

		}

	}
}
