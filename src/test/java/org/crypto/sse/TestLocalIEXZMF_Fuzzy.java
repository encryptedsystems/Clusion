package org.crypto.sse;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.crypto.sse.fuzzy.*;

import com.google.common.collect.Multimap;

/**
 * Tests Fuzzy search over encrypted data as described by A. Boldyreva
 * and N. Chenette in "Efficient Fuzzy Search on Encrypted Data". Based
 * on {@link TestLocalIEXZMF} but using {@link Fuzzy}.
 * 
 * @author Ryan Estes
 */
public class TestLocalIEXZMF_Fuzzy {
	private static final int falsePosRate = 25;
	private static final int maxLengthOfMask = 20;
	
	public static void main(String[] args) throws Exception {
		
		Printer.addPrinter(new Printer(Printer.LEVEL.DEBUG));
		//Printer.addPrinter(new Printer.FilePrinter(Printer.LEVEL.EXTRA, "data.txt"));
		
		if (!new File(Fuzzy.DICTIONARY_FILE).exists()) {
			Printer.normalln("Could not load " + Fuzzy.DICTIONARY_FILE + ".");
			Printer.normalln("Try using American 2of12 from http://wordlist.aspell.net/12dicts/");
		}

		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		Printer.normalln("Enter your password :");

		String pass = keyRead.readLine();

		List<byte[]> listSK = IEXZMF.keyGen(128, pass, "salt/salt", 100);

		Printer.normalln("Enter the relative path name of the folder that contains the files to make searchable");

		String pathName = keyRead.readLine();

		long startTime = System.nanoTime();
		TextProc.TextProc(false, pathName);
		Printer.statsln("\nTime to read files: " + (System.nanoTime() - startTime));
		
		Printer.statsln("Number of files: " + TextExtractPar.lp2.keySet().size());
		Printer.statsln("Number of keywords: " + TextExtractPar.lp1.keySet().size());
		
		Fuzzy fuzzy = new Fuzzy(new MOutOfNQueryScheme(2))
				.addFuzzingScheme(new NaturalFuzzingScheme("r"))
				.addFuzzingScheme(new StemmingCloseWordsFuzzingScheme("t")
					.addInputFilter(new ValidCharactersFilter()))
				.addFuzzingScheme(new SoundexCloseWordsFuzzingScheme("s")
					.addInputFilter(new ValidCharactersFilter()))
				.addFuzzingScheme(new MisspellingFuzzingScheme("m")
					.addInputFilter(new DictionaryFilter())
					.addOutputFilter(new SpellCheckFilter()));

		startTime = System.nanoTime();
		
		fuzzy.fuzzMultimaps(TextExtractPar.lp1);
		TextExtractPar.lp1 = fuzzy.getMultimap1();
		TextExtractPar.lp2 = fuzzy.getMultimap2();
		
		Printer.statsln("Time to produce fuzzy words: " + (System.nanoTime() - startTime));
		Printer.statsln("Number of fuzzy keywords: " + TextExtractPar.lp1.keySet().size());

		Fuzzy.printMultimap(TextExtractPar.lp2);

		Printer.debugln("\n Beginning of global encrypted multi-map construction \n");

		startTime = System.nanoTime();

		int bigBlock = 1000;
		int smallBlock = 100;
		int dataSize = 0;

		RR2Lev[] localMultiMap = null;
		Multimap<String, Integer> dictionaryForMM = null;
		// Construction by Cash et al NDSS 2014

		for (String keyword : TextExtractPar.lp1.keySet()) {

			if (dataSize < TextExtractPar.lp1.get(keyword).size()) {
				dataSize = TextExtractPar.lp1.get(keyword).size();
			}

		}

		IEX2Lev disj = new IEX2Lev(
				RR2Lev.constructEMMParGMM(listSK.get(1), TextExtractPar.lp1, bigBlock, smallBlock, dataSize),
				localMultiMap, dictionaryForMM);

		Printer.debugln("\n Beginning of local encrypted multi-map construction \n");

		IEXZMF.constructMatryoshkaPar(new ArrayList<String>(TextExtractPar.lp1.keySet()), listSK.get(0), listSK.get(1),
				maxLengthOfMask, falsePosRate);

		Printer.statsln(
				"\nTime to construct local multi-maps: " + (System.nanoTime() - startTime));

		// Beginning of search phase

		while (true) {

			Printer.normalln("How many disjunctions? Leave blank to stop.");
			int numDisjunctions = 1;
			try {
				numDisjunctions = Integer.parseInt(keyRead.readLine());
			}catch(Exception e) {
				break;
			}

			String[][] bool = new String[numDisjunctions][];
			for (int i = 0; i < numDisjunctions; i++) {
				Printer.normalln("Enter the keywords of the " + i + "th disjunctions ");
				bool[i] = keyRead.readLine().toLowerCase().split(" ");
			}
			
			startTime = System.nanoTime();
			bool = fuzzy.fuzzQuery(bool);
			Printer.statsln("Time to fuzz query: " + (System.nanoTime() - startTime));

			startTime = System.nanoTime();
			TestLocalIEXZMF.test("logZMF_Fuzzy.txt", "Test", 1, disj, listSK, bool);
			Printer.statsln("Time to run query: " + (System.nanoTime() - startTime));
		}
		
		Printer.close();
	}
}
