package org.crypto.sse.fuzzy;

import java.util.Collection;
import java.util.HashSet;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

/**
 * Produces edges between a keyword and the stem it maps to, as well as
 * between the keyword and any stem that misspellings of the keyword
 * are mapped to. Misspellings are determined by
 * {@link MisspellingFuzzingScheme}.
 * 
 * Must store a multimap from stem to keywords in order to use
 * {@link #getEdges(String)}.
 * 
 * @author Ryan Estes
 * @see {@link StemmingFuzzingScheme} {@link SoundexCloseWordsFuzzingScheme}
 */
public class StemmingCloseWordsFuzzingScheme extends IFuzzingScheme{

	private Multimap<String, String> edges = ArrayListMultimap.create();
	
	/**
	 * See {@link IFuzzingScheme#IFuzzingScheme()}.
	 */
	public StemmingCloseWordsFuzzingScheme() {}
	
	/**
	 * See {@link IFuzzingScheme#IFuzzingScheme(String)}.
	 * 
	 * @param prefix
	 */
	public StemmingCloseWordsFuzzingScheme(String prefix) {
		super(prefix);
	}

	@Override
	public void fuzzingScheme(
			String keyword,
			Multimap<String, String> origin,
			Multimap<String, String> mm1,
			Multimap<String, String> mm2) {
		
		Collection<String> codes = new HashSet<String>();
		codes.add(StemmingFuzzingScheme.getStem(keyword));
		for (String misspelling : MisspellingFuzzingScheme.getMisspellings(keyword)) {
			codes.add(StemmingFuzzingScheme.getStem(misspelling));
		}
		
		for (String file : origin.get(keyword)) {
			for (String soundex : codes) {
				insertKeyword(file, keyword, soundex, mm1, mm2);
				edges.put(soundex, keyword);
			}
		}
	}

	@Override
	public Collection<String> getEdges(String word) {
		Collection<String> results = new HashSet<String>();
		String stem = StemmingFuzzingScheme.getStem(word);
		for (String suggestion : edges.get(stem)) {
			insertEdge(results, suggestion, stem);
		}
		return results;
	}
}
