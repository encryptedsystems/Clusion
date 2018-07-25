package org.crypto.sse.fuzzy;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.google.common.collect.Multimap;

/**
 * Defines a closeness graph (or part of one) between keywords.
 * Produces edges on that closeness graph for use with
 * encrypted search. For use with {@link Fuzzy}.
 * 
 * Can be filtered using {@link IFilter}s.
 * 
 * 
 * @author Ryan Estes
 * @see {@link Fuzzy}
 */
public abstract class IFuzzingScheme {
	
	protected String prefix = "";
	private List<IFilter> inputFilters = new ArrayList<IFilter>();
	private List<IFilter> outputFilters = new ArrayList<IFilter>();
	
	/**
	 * Default constructor, leaves prefix blank.
	 */
	public IFuzzingScheme() {}
	
	/**
	 * Provide a prefix in case two or more Fuzzing Schemes produce edges
	 * of the same form as each other and would conflict. This prefix gets
	 * appended to edges produced by this scheme.
	 * 
	 * @param prefix (unique)
	 */
	public IFuzzingScheme(String prefix) {
		this.prefix = prefix;
	}
	
	/**
	 * Adds a filter that will determine whether or not a keyword
	 * should be fuzzed. For example, the {@link MisspellingFuzzingScheme}
	 * only makes sense to use on words which are not already misspelled,
	 * so using a {@link DictionaryFilter} is useful as it disallows words
	 * not found in a dictionary to be fuzzed.
	 * 
	 * @param filter to add
	 * @return this Fuzzing Scheme after the filter is added
	 * @see #addOutputFilter(IFilter)
	 */
	public IFuzzingScheme addInputFilter(IFilter filter) {
		inputFilters.add(filter);
		return this;
	}
	
	/**
	 * Adds a filter that will determine whether or not word produced
	 * by this fuzzing scheme should be used as an edge. For example,
	 * if a fuzzing scheme produces many edges, it may be desired to cut
	 * down on the total output by disallowing certain words.
	 * 
	 * @param filter to add
	 * @return this Fuzzing Scheme after the filter is added
	 * @see #addInputFilter(IFilter)
	 */
	public IFuzzingScheme addOutputFilter(IFilter filter) {
		outputFilters.add(filter);
		return this;
	}
	
	/**
	 * Takes an edge between two nodes and a prefix which represents the
	 * Fuzzing Scheme and produces a representation of it in a standard
	 * form.
	 * 
	 * @param keyword
	 * @param alternative
	 * @return
	 */
	private String getEncoding(String keyword, String alternative) {
		return prefix + ":" + keyword + ":" + alternative;
	}
	
	/**
	 * Runs an edge through all output {@link IFilter}s to determine
	 * whether or not it is valid. Then inserts the edge into the
	 * new multimaps if it is valid.
	 * 
	 * @param file Document that the original keyword is mapped to
	 * @param keyword Original keyword used to produce alternative
	 * @param alternative Word produced by this Fuzzing Scheme
	 * @param mm1 A multimap from keyword to document
	 * @param mm2 A multimap from document to keyword
	 * @return Whether or not the edge was inserted.
	 */
	protected boolean insertKeyword(
			String file,
			String keyword,
			String alternative,
			Multimap<String, String> mm1,
			Multimap<String, String> mm2) {

		boolean canInsert = true;
		for (IFilter filter : outputFilters) {
			if (!filter.checkOutput(keyword, alternative)) {
				canInsert = false;
			}
		}
		
		if (canInsert)
		{
			String insert = getEncoding(keyword, alternative);
			mm1.put(insert.intern(), file.intern());
			mm2.put(file.intern(), insert.intern());
		}
		
		return canInsert;
	}
	
	/**
	 * Runs an edge through all output {@link IFilter}s to determine
	 * whether or not it is valid. Then adds the edge to a collection
	 * of edges if it is valid.
	 * 
	 * @param edges A collection of edges to add valid edges to.
	 * @param suggestion A possible original keyword produced by this
	 * Fuzzing Scheme using word.
	 * @param word
	 * @return Whether or not the edge was inserted.
	 */
	protected boolean insertEdge(
			Collection<String> edges,
			String suggestion,
			String word) {
		
		boolean canInsert = true;
		for (IFilter filter : outputFilters) {
			if (!filter.checkOutput(suggestion, word)) {
				canInsert = false;
			}
		}
		
		if (canInsert)
		{
			edges.add(getEncoding(suggestion, word));
		}
		
		return canInsert;
	}
	
	/**
	 * Runs a keyword through all input {@link IFilter}s to determine
	 * whether or not it can be fuzzed by this scheme. If it can,
	 * procede to
	 * {@link #fuzzingScheme(String, Multimap, Multimap, Multimap)}.
	 * 
	 * @param keyword to fuzz if it passes all {@link IFilter}s
	 * @param origin Original multimap from keyword to document which
	 * is being fuzzed.
	 * @param mm1 New multimap from keyword to document.
	 * @param mm2 New multimap from document to keyword.
	 */
	public void fuzz(
			String keyword,
			Multimap<String, String> origin,
			Multimap<String, String> mm1,
			Multimap<String, String> mm2) {
		
		boolean canFuzz = true;
		for (IFilter filter : inputFilters) {
			if (!filter.checkInput(keyword)) {
				canFuzz = false;
			}
		}
		
		if (canFuzz) {
			fuzzingScheme(keyword, origin, mm1, mm2);
		}
	}
	
	/**
	 * Takes a keyword and a keyword-to-document multimap and produces
	 * fuzzy connections 
	 * 
	 * @param keyword
	 * @param origin
	 * @param mm1
	 * @param mm2
	 */
	protected abstract void fuzzingScheme(
			String keyword,
			Multimap<String, String> origin,
			Multimap<String, String> mm1,
			Multimap<String, String> mm2);
	
	public abstract Collection<String> getEdges(String word);
}
