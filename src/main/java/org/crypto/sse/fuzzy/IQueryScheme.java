package org.crypto.sse.fuzzy;

import java.util.List;

/**
 * Modifies the form of a query. Uses a list of lists as input and output.
 * Made with conjunctive normal form queries in mind but could be used
 * for other forms of queries.
 * 
 * @author Ryan Estes
 * @see {@link Fuzzy}
 */
public abstract class IQueryScheme {

	/**
	 * See description of {@link IQueryScheme}.
	 * 
	 * @param query
	 * @return The modified query in conjunctive normal form (unless otherwise
	 * specified by the Query Scheme.
	 */
	public abstract List<List<String>> modifyQuery(List<List<String>> query);
	
}
