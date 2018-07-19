package org.crypto.sse.fuzzy;

import java.util.ArrayList;
import java.util.List;

import com.google.common.collect.Multimap;

/**
 * Produces an "edge" which is just the keyword unmodified. Used when searching
 * for exact matches.
 * 
 * @author Ryan Estes
 */
public class NaturalFuzzingScheme extends IFuzzingScheme{

	/**
	 * See {@link IFuzzingScheme#IFuzzingScheme()}.
	 */
	public NaturalFuzzingScheme() {}

	/**
	 * See {@link IFuzzingScheme#IFuzzingScheme(String)}.
	 * 
	 * @param prefix
	 */
	public NaturalFuzzingScheme(String prefix) {
		super(prefix);
	}

	@Override
	public void fuzzingScheme(String keyword, Multimap<String, String> origin, Multimap<String, String> mm1,
			Multimap<String, String> mm2) {
		for (String file : origin.get(keyword)) {
			insertKeyword(file, keyword, "", mm1, mm2);
		}
	}

	@Override
	public List<String> getEdges(String word) {
		List<String> edges = new ArrayList<String>();
		insertEdge(edges, word, "");
		return edges;
	}
}
