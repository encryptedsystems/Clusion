package org.crypto.sse.fuzzy;

import java.util.ArrayList;
import java.util.List;

import org.tartarus.snowball.ext.PorterStemmer;

import com.google.common.collect.Multimap;

/**
 * Produces pseudo edges between the stem that a keyword maps to
 * and all keywords that map to that stem.
 * 
 * https://en.wikipedia.org/wiki/Stemming
 * 
 * @author Ryan Estes
 * @see {@link StemmingCloseWordsFuzzingScheme}
 */
public class StemmingFuzzingScheme extends IFuzzingScheme {

	final private static PorterStemmer STEMMER = new PorterStemmer();
	
	/**
	 * See {@link IFuzzingScheme#IFuzzingScheme()}.
	 */
	public StemmingFuzzingScheme() {}
	
	/**
	 * See {@link IFuzzingScheme#IFuzzingScheme(String)}.
	 * 
	 * @param prefix
	 */
	public StemmingFuzzingScheme(String prefix) {
		super(prefix);
	}
	
	@Override
	public void fuzzingScheme(
			String keyword,
			Multimap<String, String> origin,
			Multimap<String, String> mm1,
			Multimap<String, String> mm2) {
		
		for (String file : origin.get(keyword)) {
			String stem = getStem(keyword);
			insertKeyword(file, "", stem, mm1, mm2);
		}
	}

	@Override
	public List<String> getEdges(String word) {
		List<String> edges = new ArrayList<String>();
		insertEdge(edges, "", getStem(word));
		return edges;
	}
	
	public static String getStem(String word) {
		STEMMER.setCurrent(word);
		STEMMER.stem();
		return STEMMER.getCurrent();
	}
}
