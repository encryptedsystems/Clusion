//***********************************************************************************************//
// This file is to test the DynRH construction tht handles addition and delete operations
//**********************************************************************************************


package org.clusion;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;

public class TestLocalDynRHAndroid {

	public static void main(String[] args) throws Exception {


		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		System.out.println("Enter your password :");

		String pass = keyRead.readLine();

		byte[] sk = DynRHAndroid.keyGen(256, pass, "salt/salt", 100000);

		Multimap<String, String> lp1 = ArrayListMultimap.create();
		lp1.put("doc1", "toto"); 

		// Construction of the encrypted multi-map
		// This operation will simply generate a dictionary on the server side
		// The setup will be performed as multiple update operations
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");
		HashMap<String, byte[]> emm = DynRHAndroid.setup();

		// Generate the updates
		// This operation will generate update tokens for the entire data set
		TreeMultimap<String, byte[]> tokenUp = DynRHAndroid.tokenUpdate(sk, lp1);

		// Update the encrypted Multi-map
		// the dictionary is updated on the server side
		DynRHAndroid.update(emm, tokenUp);

		// Empty the previous multimap
		// to avoid adding the same set of documents for every update

		lp1 = ArrayListMultimap.create();

		// Update phase

		lp1.put("doc2", "mino"); 

		// This operation is similar to the one performed above
		tokenUp = DynRHAndroid.tokenUpdate(sk, lp1);
		DynRHAndroid.update(emm, tokenUp);

		System.out.println("Enter 1 for forward secure search and anything otherwise:");

		String pathName = keyRead.readLine();

		if (pathName.equals("1")) {

			while (true) {

				System.out.println("Enter the keyword to search for:");
				String keyword = keyRead.readLine();
				byte[][] token = DynRHAndroid.genTokenFS(sk, keyword);

				System.out.println(DynRHAndroid.resolve(sk, DynRHAndroid.queryFS(token, emm), keyword));

				System.out.println("Enter index of the identifier that you want to delete:");
				String index = keyRead.readLine();
				List<Integer> deletions = new ArrayList<Integer>();
				deletions.add(Integer.parseInt(index));
				byte[][] delToken = DynRHAndroid.delTokenFS(sk, keyword, deletions);
				DynRHAndroid.deleteFS(delToken, emm);

			}
		} else {
			while (true) {
				System.out.println("Enter the keyword to search for:");
				String keyword = keyRead.readLine();
				byte[][] token = DynRHAndroid.genToken(sk, keyword);

				System.out.println(DynRHAndroid.resolve(sk, DynRHAndroid.query(token, emm), keyword));

//				System.out.println("Enter index of the identifier that you want to delete:");
//				String index = keyRead.readLine();
//				List<Integer> deletions = new ArrayList<Integer>();
//				deletions.add(Integer.parseInt(index));
//				byte[] delToken = DynRHAndroid.delToken(sk, keyword);
//				DynRHAndroid.delete(delToken, deletions, emm);

			}
		}

	}
}
