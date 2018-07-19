package org.crypto.sse.fuzzy;

import java.util.ArrayList;
import java.util.List;

/**
 * Produces an M out of N query in conjunctive normal form. For each
 * list of strings in the input, the query is expanded to require
 * the query to match M of those strings. In other words, the output
 * query tests for results which match M out of the first list of strings
 * in the input query, AND M out of the second, and so on...
 * 
 * @author Ryan Estes
 */
public class MOutOfNQueryScheme extends IQueryScheme{

	private int m;
	
	/**
	 * Specify the number of elements each list of strings in the
	 * input query must match.
	 * 
	 * @param m
	 */
	public MOutOfNQueryScheme(int m) {
		this.m = m;
	}
	
	@Override
	public List<List<String>> modifyQuery(List<List<String>> query) {
		
		List<List<String>> results = new ArrayList<List<String>>();
		
		for (List<String> nList : query) {
			int literals = nList.size() - m + 1;
			if (literals < 1)
				literals = 1;

			ArrayList<String> workingList = new ArrayList<String>();
			populateResults(results, workingList, nList, 0, literals);
		}
		
		return results;
	}

	private void populateResults(
			List<List<String>> results,
			ArrayList<String> workingList,
			List<String> nList,
			int index,
			int numLeft) {

		if (numLeft > 0) {
			for (int i = index; i < nList.size() - numLeft + 1; ++i)
			{
				workingList.add(nList.get(i));
				populateResults(results, workingList, nList, i + 1, numLeft - 1);
				workingList.remove(workingList.size() - 1);
			}
		} else {
			results.add(new ArrayList<String>(workingList));
		}
	}
}
