//***********************************************************************************************//
// This file is to test the DynRH construction that handles add and delete operations on Disk
//**********************************************************************************************

package org.crypto.sse;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.crypto.NoSuchPaddingException;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;

public class TestLocalDynRH_DISK {

	static int counter = 0;

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

		// Construction of the encrypted multi-map

		// The setup will be performed as multiple update operations
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");

		ConcurrentMap<String, byte[]> dictionaryUpdates = DynRH_Disk.setup();

		// Generate the updates

		// This operation will generate update tokens for the entire data set

		System.out.println("Number of keywords " + TextExtractPar.lp1.keySet().size());
		System.out.println("Number of pairs " + TextExtractPar.lp1.keys().size());

		// parallel insertion in the mapDB

		// start
		long startTime = System.nanoTime();
		int threads = 0;
		if (Runtime.getRuntime().availableProcessors() > TextExtractPar.lp1.keySet().size()) {
			threads = TextExtractPar.lp1.keySet().size();
		} else {
			threads = Runtime.getRuntime().availableProcessors();
		}

		ExecutorService service = Executors.newFixedThreadPool(threads);
		ArrayList<String[]> inputs = new ArrayList<String[]>(threads);

		System.out.println("\n\nNumber of Threads " + threads);

		Iterator<String> it = TextExtractPar.lp1.keySet().iterator();
		for (int i = 0; i < threads; i++) {
			String[] tmp;
			if (i == threads - 1) {
				tmp = new String[TextExtractPar.lp1.keySet().size() / threads
						+ TextExtractPar.lp1.keySet().size() % threads];
				for (int j = 0; j < TextExtractPar.lp1.keySet().size() / threads
						+ TextExtractPar.lp1.keySet().size() % threads; j++) {
					tmp[j] = it.next();
				}
			} else {
				tmp = new String[TextExtractPar.lp1.keySet().size() / threads];
				for (int j = 0; j < TextExtractPar.lp1.keySet().size() / threads; j++) {
					tmp[j] = it.next();
				}
			}
			inputs.add(i, tmp);
		}

		for (final String[] input : inputs) {
			service.execute(new Runnable() {
				public void run() {

					for (String keyword : input) {
						for (int j = 0; j < 100; j++) {
							if (counter == (int) ((j + 1) * TextExtractPar.lp1.keySet().size() / 100)) {
								System.out.println("Number of keywords processed " + j + " %");
								break;
							}
						}
						Multimap<String, String> lookup = ArrayListMultimap.create();
						lookup.putAll(keyword, TextExtractPar.lp1.get(keyword));
						TreeMultimap<String, byte[]> tokenUp = null;
						try {
							tokenUp = DynRH_Disk.tokenUpdate(sk, lookup);
						} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
								| NoSuchProviderException | NoSuchPaddingException | IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						DynRH_Disk.update(dictionaryUpdates, tokenUp);
						counter++;
					}

				}
			});
		}

		// Make sure executor stops
		service.shutdown();

		// Blocks until all tasks have completed execution after a shutdown
		// request
		service.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);

		// end
		long endTime = System.nanoTime();

		// time elapsed
		long output = endTime - startTime;

		System.out.println("\nElapsed time in seconds: " + output / 1000000000);

		System.out.println("\nEnter 1 for forward secure search and anything otherwise:");

		pathName = keyRead.readLine();

		int count = 10;
		if (pathName.equals("1")) {

			while (count > 0) {

				System.out.println("Enter the keyword to search for:");

				String keyword = keyRead.readLine();

				byte[][] token = DynRH_Disk.genTokenFS(sk, keyword);

				// start
				startTime = System.nanoTime();

				List<String> result = DynRH_Disk.resolve(sk, DynRH_Disk.queryFS(token, dictionaryUpdates));

				// end
				endTime = System.nanoTime();

				// time elapsed
				output = endTime - startTime;

				System.out.println(result);
				System.out.println("\nElapsed time in microseconds: " + output / 1000);

				if (result.size() > 0) {
					System.out.println("Enter index of the identifier that you want to delete:");
					String index = keyRead.readLine();
					List<Integer> deletions = new ArrayList<Integer>();
					deletions.add(Integer.parseInt(index));
					byte[][] delToken = DynRH_Disk.delTokenFS(sk, keyword, deletions);
					DynRH_Disk.deleteFS(delToken, dictionaryUpdates);
				}
				count--;
			}
		} else {
			while (count > 0) {
				System.out.println("Enter the keyword to search for:");
				String keyword = keyRead.readLine();
				byte[][] token = DynRH_Disk.genToken(sk, keyword);

				// start
				startTime = System.nanoTime();
				List<String> result = DynRH_Disk.resolve(sk, DynRH_Disk.query(token, dictionaryUpdates));

				// end
				endTime = System.nanoTime();

				// time elapsed
				output = endTime - startTime;
				System.out.println(result);

				System.out.println("\nElapsed time in microseconds: " + output / 1000);
				if (result.size() > 0) {
					System.out.println("Enter index of the identifier that you want to delete:");
					String index = keyRead.readLine();
					List<Integer> deletions = new ArrayList<Integer>();
					deletions.add(Integer.parseInt(index));
					byte[] delToken = DynRH_Disk.delToken(sk, keyword);
					DynRH_Disk.delete(delToken, deletions, dictionaryUpdates);
				}
				count--;

			}
		}
	}
}
