package org.crypto.sse.fuzzy;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.language.Soundex;

import com.google.common.collect.Multimap;

/**
 * Produces pseudo edges between the soundex that a keyword maps to
 * and all keywords that map to that soundex.
 * 
 * https://en.wikipedia.org/wiki/Soundex
 * 
 * @author Ryan Estes
 * @see {@link SoundexCloseWordsFuzzingScheme}
 */
public class SoundexFuzzingScheme extends IFuzzingScheme {
	
	Soundex soundex = new Soundex();
	
	/**
	 * See {@link IFuzzingScheme#IFuzzingScheme()}.
	 */
	public SoundexFuzzingScheme() {}
	
	/**
	 * See {@link IFuzzingScheme#IFuzzingScheme(String)}
	 * 
	 * @param prefix
	 */
	public SoundexFuzzingScheme(String prefix) {
		super(prefix);
	}

	@Override
	public void fuzzingScheme(
			String keyword,
			Multimap<String, String> origin,
			Multimap<String, String> mm1,
			Multimap<String, String> mm2) {
		
		String code = soundex.encode(keyword);
		for (String file : origin.get(keyword)) {
			insertKeyword(file, "", code, mm1, mm2);
		}
	}

	@Override
	public List<String> getEdges(String word) {
		List<String> edges = new ArrayList<String>();
		insertEdge(edges, "", soundex.encode(word));
		return edges;
	}
}
