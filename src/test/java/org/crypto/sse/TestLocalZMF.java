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

/*
 * This class is a test for the ZMF construction. 
 * It tests for conjunctive queries where the client outputs two keywords that he wants to search for and the search will output the number of documents that contain 
 * both keywords.
 * 
 * This construction takes as inputs,  in particular, a false positive rate and a maximum mask length that determines the longest filter that can be handled. 
 */

package org.crypto.sse;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class TestLocalZMF {
	public static void main(String[] args) throws Exception {

		int falsePosRate = 20;
		int maxMaxLength = 20;

		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		System.out.println("Enter your password :");

		String pass = keyRead.readLine();

		byte[] sk = ZMF.keyGenSM(128 * 3, pass, "salt/salt", 100);

		long startTime = System.nanoTime();

		BufferedWriter writer = new BufferedWriter(new FileWriter("logs.txt", true));

		System.out.println("Enter the relative path name of the folder that contains the files to make searchable:");

		String pathName = keyRead.readLine();

		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);

		TextProc.TextProc(false, pathName);

		System.out.println("Enter the first keyword to search for:");
		String keywordONE = keyRead.readLine();

		// Construction of the ZMF Matryoshka filters

		Map<String, boolean[]> zmf = ZMF.setupSetMV2(sk, keywordONE, TextExtractPar.lp2, TextExtractPar.lp1,
				falsePosRate);

		while (true) {

			System.out.println("Enter the keyword to search for the conjunction:");
			String keywordTWO = keyRead.readLine();

			List<byte[]> token = ZMF.genTokSMV2(sk, keywordONE, keywordTWO, maxMaxLength, falsePosRate);

			ZMF.testSMV2(zmf, token, falsePosRate);

			System.out.println("The matching documents are: " + ZMF.results);

		}

	}

}
