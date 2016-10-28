/*
 * This Class tests the text processing functionality
 * It outputs two multi-maps: the first associates keywords to the documents identifiers while the second associates the doc identifiers to keywords
 */

package org.crypto.sse;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class TestIndexing {

	public static void main(String[] args) throws Exception {

		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		System.out.println("Enter the relative path name of the folder that contains the files to make searchable:");

		String pathName = keyRead.readLine();

		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);

		TextProc.TextProc(false, pathName);

		System.out.println("First mult-map " + TextExtractPar.lp1);
		System.out.println("Second multi-map " + TextExtractPar.lp1);

	}

}
