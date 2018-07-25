package org.crypto.sse.fuzzy;

import java.util.ArrayList;
import java.util.List;

import org.crypto.sse.Printer;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

/**
 * Applies {@link IFuzzingScheme}s to encrypted search methods which use
 * {@link com.google.common.collect.Multimap}s to initialize an encrypted
 * database and use queries in conjunctive normal form. Optionally uses an
 * {@link IQueryScheme} to modify an entire query.
 * 
 * @author Ryan Estes
 * @see {@link IFuzzingScheme} {@link IQueryScheme} {@link IFilter}
 */
public class Fuzzy {
	
	final public static String DICTIONARY_FILE = "dictionary.txt";
	
	private Multimap<String, String> mm1;
	private Multimap<String, String> mm2;

	private List<IFuzzingScheme> fuzzingSchemes = new ArrayList<IFuzzingScheme>();
	private IQueryScheme queryScheme = null;
	
	/**
	 * Default constructor.
	 */
	public Fuzzy() {}
	
	/**
	 * Constructor specifying optional Query Scheme.
	 * 
	 * @param queryScheme Optional Query Scheme to be applied after 
	 * producing fuzzy keywords for query.
	 * {@link IQueryScheme}
	 */
	public Fuzzy(IQueryScheme queryScheme) {
		this.queryScheme = queryScheme;
	}
	
	/**
	 * Use after running {@link #fuzzMultimaps(Multimap)} to get
	 * the multimap that maps keywords to documents.
	 * 
	 * @return Like {@link org.crypto.sse.TextExtractPar#getL1()}
	 * but using fuzzy terms as described by fuzzing schemes added
	 * with {@link #addFuzzingScheme(IFuzzingScheme)}.
	 */
	public Multimap<String, String> getMultimap1(){
		return mm1;
	}
	
	/**
	 * Use after running {@link #fuzzMultimaps(Multimap)} to get
	 * the multimap that maps documents to keywords.
	 * 
	 * @return Like {@link org.crypto.sse.TextExtractPar#getL2()}
	 * but using fuzzy terms as described by fuzzing schemes added
	 * with {@link #addFuzzingScheme(IFuzzingScheme)}.
	 */
	public Multimap<String, String> getMultimap2(){
		return mm2;
	}
	
	/**
	 * Adds an {@link IFuzzingScheme} to an ordered list of schemes
	 * which will be applied during {@link #fuzzMultimaps(Multimap)}.
	 * Altogether, the list of Fuzzing Schemes define a closeness graph
	 * between keywords.
	 * 
	 * @param fuzzingScheme
	 * @return this Fuzzy after adding a Fuzzing Scheme
	 */
	public Fuzzy addFuzzingScheme(IFuzzingScheme fuzzingScheme) {
		fuzzingSchemes.add(fuzzingScheme);
		return this;
	}
	
	/**
	 * Applies all {@link IFuzzingScheme}s added with
	 * {@link #addFuzzingScheme(IFuzzingScheme)} to a multimap
	 * of keywords and documents and saves results to
	 * {@link #getMultimap1()} and {@link #getMultimap2()}.
	 * 
	 * @param origin Multimap mapping keywords to documents.
	 * Like {@link org.crypto.sse.TextExtractPar#getL1()}
	 */
	public void fuzzMultimaps (Multimap<String, String> origin) {
		mm1 = ArrayListMultimap.create();
		mm2 = ArrayListMultimap.create();
		
		for (String key : origin.keySet()) {
			for (IFuzzingScheme fuzzingScheme : fuzzingSchemes) {
				fuzzingScheme.fuzz(key, origin, mm1, mm2);
			}
		}
	}
	
	/**
	 * Applies all {@link IFuzzingScheme}s added with
	 * {@link #addFuzzingScheme(IFuzzingScheme)} to each keyword
	 * in a query, then applies optional {@link IQueryScheme} if
	 * added in {@link #Fuzzy(IQueryScheme)} to the query.
	 * 
	 * @param query in conjunctive normal form (unless otherwise
	 * specified by an {@link IQueryScheme}).
	 * @return Fuzzed query in conjunctive normal form.
	 */
	public String[][] fuzzQuery(String[][] query) {
		List<List<String>> results = new ArrayList<List<String>>();
		
		for (int i = 0; i < query.length; ++i) {
			List<String> disjunction = new ArrayList<String>();
			for (int j = 0; j < query[i].length; ++j) {
				if (fuzzingSchemes.size() == 0) {
					disjunction.add(query[i][j]);
				} else {
					for (IFuzzingScheme fuzzingScheme : fuzzingSchemes) {
						disjunction.addAll(fuzzingScheme.getEdges(query[i][j]));
					}
				}
			}
			
			results.add(disjunction);
		}
		
		if (queryScheme != null) {
			results = queryScheme.modifyQuery(results);
		}
		
		query = new String[results.size()][];
		
		for (int i = 0; i < results.size(); ++i) {
			List<String> disjunction = results.get(i);
			query[i] = new String[disjunction.size()];
			Printer.debugln("(");
			for (int j = 0; j < disjunction.size(); ++j) {
				Printer.debugln("\t"+disjunction.get(j));
				query[i][j] = disjunction.get(j);
			}
			Printer.debug(")");
		}
		
		Printer.debugln("");
		
		return query;
	}
	
	/**
	 * Debugging tool for printing multimaps in an easy to read
	 * way. Must have {@link org.crypto.sse.Printer} set to
	 * DEBUG or a more detailed level. 
	 * 
	 * @param mm Multimap to print.
	 */
	public static void printMultimap(Multimap<String,String> mm) {
		int numKeys = 0;
		int numElements = 0;
		for (String key : mm.keySet()) {
			++numKeys;
			Printer.debugln(key);
			for (String word : mm.get(key)) {
				++numElements;
				Printer.debugln("\t" + word);
			}
		}
		Printer.debugln("Number of Keys: " + numKeys + ". Number of Elements: " + numElements);
	}
	
}
