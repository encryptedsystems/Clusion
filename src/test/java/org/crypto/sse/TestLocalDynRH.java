//***********************************************************************************************//
// This file is to test the DynRH construction tht handles addition and delete operations
//**********************************************************************************************

package org.crypto.sse;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;

public class TestLocalDynRH {

	public static void main(String[] args) throws Exception {

		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		System.out.println("Enter your password :");

		String pass = keyRead.readLine();

		byte[] sk = RR2Lev.keyGen(256, pass, "salt/salt", 100000);

		System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

		String pathName = keyRead.readLine();

		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);

		TextProc.TextProc(false, pathName);

		// Construction of the encrypted multi-map
		// This operation will simply generate a dictionary on the server side
		// The setup will be performed as multiple update operations
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");
		HashMap<String, byte[]> emm = DynRH.setup();

		// Generate the updates
		// This operation will generate update tokens for the entire data set
		TreeMultimap<String, byte[]> tokenUp = DynRH.tokenUpdate(sk, TextExtractPar.lp1);

		// Update the encrypted Multi-map
		// the dictionary is updated on the server side
		DynRH.update(emm, tokenUp);

		// Empty the previous multimap
		// to avoid adding the same set of documents for every update

		TextExtractPar.lp1 = ArrayListMultimap.create();

		// Update phase

		System.out.println("Enter the relative path name of the folder that contains the files to add:");

		pathName = keyRead.readLine();

		listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);
		TextProc.TextProc(false, pathName);

		// This operation is similar to the one performed above
		tokenUp = DynRH.tokenUpdate(sk, TextExtractPar.lp1);
		DynRH.update(emm, tokenUp);

		System.out.println("Enter 1 for forward secure search and anything otherwise:");

		pathName = keyRead.readLine();

		if (pathName.equals("1")) {

			while (true) {

				System.out.println("Enter the keyword to search for:");
				String keyword = keyRead.readLine();
				byte[][] token = DynRH.genTokenFS(sk, keyword);

				System.out.println(DynRH.resolve(sk, DynRH.queryFS(token, emm), keyword));

				System.out.println("Enter index of the identifier that you want to delete:");
				String index = keyRead.readLine();
				List<Integer> deletions = new ArrayList<Integer>();
				deletions.add(Integer.parseInt(index));
				byte[][] delToken = DynRH.delTokenFS(sk, keyword, deletions);
				DynRH.deleteFS(delToken, emm);

			}
		} else {
			while (true) {
				System.out.println("Enter the keyword to search for:");
				String keyword = keyRead.readLine();
				byte[][] token = DynRH.genToken(sk, keyword);

				System.out.println(DynRH.resolve(sk, DynRH.query(token, emm), keyword));

				System.out.println("Enter index of the identifier that you want to delete:");
				String index = keyRead.readLine();
				List<Integer> deletions = new ArrayList<Integer>();
				deletions.add(Integer.parseInt(index));
				byte[] delToken = DynRH.delToken(sk, keyword);
				DynRH.delete(delToken, deletions, emm);

			}
		}

	}
}
