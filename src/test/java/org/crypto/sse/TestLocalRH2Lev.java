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
// This file is to test the 2Lev construction by Cash et al. NDSS'14. 
//**********************************************************************************************

package org.crypto.sse;

import java.io.*;
import java.util.ArrayList;

public class TestLocalRH2Lev {

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

		// The two parameters depend on the size of the data set. Change
		// accordingly to have better search performance
		int bigBlock = 1000;
		int smallBlock = 100;
		int dataSize = 10000;

		// Construction of the global multi-map
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");
		System.out.println("Number of keywords "+TextExtractPar.lp1.keySet().size());
		System.out.println("Number of pairs "+	TextExtractPar.lp1.keys().size());
		//start
        long startTime = System.nanoTime();
		RH2Lev twolev = RH2Lev.constructEMMParGMM(sk, TextExtractPar.lp1, bigBlock, smallBlock, dataSize);
		//end
        long endTime = System.nanoTime();

		//time elapsed
        long output = endTime - startTime;

        System.out.println("Elapsed time in seconds: " + output / 1000000000);			
        
		while (true) {

			System.out.println("Enter the keyword to search for:");
			String keyword = keyRead.readLine();
			byte[][] token = RH2Lev.token(sk, keyword);
			System.out.println(RH2Lev.resolve(CryptoPrimitives.generateCmac(sk, 3 + new String()),
					twolev.query(token, twolev.getDictionary(), twolev.getArray())));

		}

	}
}
