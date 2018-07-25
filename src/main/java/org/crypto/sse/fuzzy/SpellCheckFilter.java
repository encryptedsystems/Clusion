package org.crypto.sse.fuzzy;

import java.util.List;

/**
 * Filters alternatives by whether or not a spell checker's first guess when
 * checking it is the keyword that the it was derived from. 
 * 
 * Only used as an output filter.
 * 
 * @author Ryan Estes
 */
public class SpellCheckFilter extends IFilter{

	@Override
	protected boolean inputFilter(String keyword) {
		return true;
	}

	@Override
	protected boolean outputFilter(String keyword, String alternative) {
		List<String> suggestions = LanguageTools.getInstance().JAZZY.getSuggestions(alternative);
		return suggestions.size() > 0 && keyword.equals(suggestions.get(0));
	}

}
