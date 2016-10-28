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
	

		public static void main(String[] args) throws Exception{

			BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

			System.out.println("Enter your password :");

			String pass	=	keyRead.readLine();

			byte[] sk	=	MMGlobal.keyGenSI(256, pass, "salt/salt", 100);


			System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

			String pathName	=	keyRead.readLine();

			ArrayList<File> listOfFile=new ArrayList<File>();
			TextProc.listf(pathName, listOfFile); 

			TextProc.TextProc(false, pathName);

			//The two parameters depend on the size of the dataset. Change accordingly to have better search performance
			int bigBlock	=	1000;
			int smallBlock	=	100;
			int dataSize	=	10000;

			//Construction of the global multi-map
			System.out.println("\nBeginning of Global MM creation \n");

			RH2Lev.master = sk;
		
			RH2Lev twolev	=	RH2Lev.constructEMMParGMM(sk, TextExtractPar.lp1, bigBlock, smallBlock, dataSize);


			while (true){

				System.out.println("Enter the keyword to search for:");
				String keyword	=	keyRead.readLine();
				byte[][] token = MMGlobal.genToken(sk, keyword);
				
				
				System.out.println(RH2Lev.resolve(CryptoPrimitives.generateCmac(sk, 3+new String()),
						twolev.testSI(token, twolev.getDictionary(), twolev.getArray())));
				
				
				
			}

		}
	}



