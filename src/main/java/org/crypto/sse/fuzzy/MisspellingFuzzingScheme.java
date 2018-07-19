package org.crypto.sse.fuzzy;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

/**
 * Uses rules to produce possible misspellings in English language.
 * 
 * @author Ryan Estes
 */
public class MisspellingFuzzingScheme extends IFuzzingScheme{
	
	final private static String MISSPELLING_RULES_FILE = "MisspellingRules.txt";
	final private static List<Family> FAMILIES = new ArrayList<Family>();
	final private static Multimap<String, String> MISSPELLINGS = ArrayListMultimap.create();
	final private static Multimap<String, String> SUGGESTIONS = ArrayListMultimap.create();

	/**
	 * @see {@link IFuzzingScheme#IFuzzingScheme()}
	 */
	public MisspellingFuzzingScheme() {}
	
	/**
	 * @see {@link IFuzzingScheme#IFuzzingScheme(String)}.
	 * @param prefix
	 */
	public MisspellingFuzzingScheme(String prefix) {
		super(prefix);
	}

	@Override
	public void fuzzingScheme(
			String keyword,
			Multimap<String, String> origin,
			Multimap<String, String> mm1,
			Multimap<String, String> mm2) {
		
		Collection<String> fuzzyWords = getMisspellings(keyword);
		
		for (String file : origin.get(keyword)) {
			for (String word : fuzzyWords) {
				insertKeyword(file, keyword, word, mm1, mm2);
			}
		}
	}

	@Override
	public List<String> getEdges(String word) {
		List<String> edges = new ArrayList<String>();
		
		for (String suggestion : LanguageTools.getInstance().JAZZY.getSuggestions(word)) {
			if (!suggestion.equals(word)) {
				insertEdge(edges, suggestion, word);
			}
		}
		
		return edges;
	}
	
	public static Collection<String> getMisspellings(String str) {
		if (MISSPELLINGS.containsKey(str)) {
			return MISSPELLINGS.get(str);
		} else {
			List<String> fuzzyWords = new ArrayList<String>();
			for (Family family : FAMILIES) {
				family.apply(str, fuzzyWords);
			}
			return fuzzyWords;
		}
	}
	
	public static Collection<String> getSuggestions(String str) {
		return SUGGESTIONS.get(str);
	}
	
	static {
		try {
			BufferedReader misspelledRulesReader = new BufferedReader (new FileReader(MISSPELLING_RULES_FILE));
			String line;
			
			FAMILIES.add(new Family());
			Family current = new Family();
			
			while ((line = misspelledRulesReader.readLine()) != null) {
				if (line.equals("")) {
					current.compilePatterns();
					FAMILIES.add(current);
					current = new Family();
				} else if (line.startsWith("!")) {
					current.modify(line);
				} else {
					current.addWord(line);
				}
			}
			
			current.compilePatterns();
			FAMILIES.add(current);
			
			misspelledRulesReader.close();
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private static class Family {
		private String frontStr = "";
		private String backStr = "";
		private int frontNum = 0;
		private int backNum = 0;
		private List<Pattern> patterns = new ArrayList<Pattern>();
		private List<String> sequences = new ArrayList<String>();
		
		public void modify(String modification) {
			switch(modification) {
			case "!s": //Starts a word
				frontStr = "\\A";
				break;
			case "!e": //Ends a word
				backStr = "\\z";
				break;
			case "!ns": //Does not start a word
				frontNum = 1;
				frontStr = "\\S";
				break;
			case "!ne": //Does not end a word
				backNum = 1;
				backStr = "\\S";
				break;
			}
		}
		
		public void addWord(String word) {
			sequences.add(word);
		}
		
		public void compilePatterns() {
			for (String word : sequences) {
				patterns.add(Pattern.compile(frontStr + word + backStr));
			}
		}
		
		public void apply(String str, List<String> results){
			for (int patternIndex = 0; patternIndex < patterns.size(); ++patternIndex) {
				
				Matcher matcher = patterns.get(patternIndex).matcher(str);
				if (matcher.find()) {
					int resultSize = results.size();
					
					for (int i = 0; i < resultSize; ++i) {
						results.addAll(applyRule(results.get(i), patternIndex, str));
					}
					results.addAll(applyRule(str, patternIndex, str));
					
					break;
				}
			}
		}
		
		private List<String> applyRule (String str, int index, String original) {
			List<String> results = new ArrayList<String>();
			Matcher matcher = patterns.get(index).matcher(str);
			
			while (matcher.find()) {
				for (int i = 0; i < sequences.size(); ++i)
				{
					if (index != i) {
						String misspelling =
								str.substring(0, matcher.start() + frontNum)
								+ sequences.get(i)
								+ str.substring(matcher.end() - backNum).intern();
					
						results.add(misspelling);
						MISSPELLINGS.put(original, misspelling);
						SUGGESTIONS.put(misspelling, original);
					}
				}
			}
			
			return results;
		}
	}
}
