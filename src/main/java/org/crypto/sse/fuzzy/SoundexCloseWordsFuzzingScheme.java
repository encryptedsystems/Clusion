package org.crypto.sse.fuzzy;

import java.util.Collection;
import java.util.HashSet;

import org.apache.commons.codec.language.Soundex;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

/**
 * Produces edges between a keyword and the soundex it maps to, as well as
 * between the keyword and any soundecies that misspellings of the keyword
 * are mapped to. Misspellings are determined by
 * {@link MisspellingFuzzingScheme}.
 * 
 * Must store a multimap from soundex to keywords in order to use
 * {@link #getEdges(String)}.
 * 
 * @author Ryan Estes
 * @see {@link SoundexFuzzingScheme} {@link StemmingCloseWordsFuzzingScheme}
 */
public class SoundexCloseWordsFuzzingScheme extends IFuzzingScheme{
	
	Soundex soundex = new Soundex();
	
	private Multimap<String, String> edges = ArrayListMultimap.create();
	
	/**
	 * See {@link IFuzzingScheme#IFuzzingScheme()}.
	 */
	public SoundexCloseWordsFuzzingScheme() {}
	
	/**
	 * See {@link IFuzzingScheme#IFuzzingScheme(String)}.
	 * 
	 * @param prefix
	 */
	public SoundexCloseWordsFuzzingScheme(String prefix) {
		super(prefix);
	}

	@Override
	public void fuzzingScheme(
			String keyword,
			Multimap<String, String> origin,
			Multimap<String, String> mm1,
			Multimap<String, String> mm2) {
		
		Collection<String> codes = new HashSet<String>();
		codes.add(soundex.encode(keyword));
		for (String misspelling : MisspellingFuzzingScheme.getMisspellings(keyword)) {
			codes.add(soundex.encode(misspelling));
		}
		
		for (String file : origin.get(keyword)) {
			for (String code : codes) {
				insertKeyword(file, keyword, code, mm1, mm2);
				edges.put(code, keyword);
			}
		}
	}

	@Override
	public Collection<String> getEdges(String word) {
		Collection<String> results = new HashSet<String>();
		String code = soundex.encode(word);
		for (String suggestion : edges.get(code)) {
			insertEdge(results, suggestion, code);
		}
		return results;
	}
}
