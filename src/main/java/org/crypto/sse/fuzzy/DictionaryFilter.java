package org.crypto.sse.fuzzy;

import java.util.Hashtable;
import java.util.List;

/**
 * Filters words by checking to see if they appear in a dictionary (defined by
 * {@link Fuzzy}.
 * 
 * @author Ryan Estes
 */
public class DictionaryFilter extends IFilter{

	private static Hashtable<String, Boolean> words = new Hashtable<String, Boolean>();
	
	@Override
	public boolean inputFilter(String keyword) {
		if (words.contains(keyword)) {
			return words.get(keyword);
		}
		else {
			//Hacky way to check if the word is in the dictionary
			List<String> fixed = LanguageTools.getInstance().JAZZY.getSuggestions(keyword);
			boolean result = fixed.size() > 0 && fixed.get(0).equals(keyword);
			words.put(keyword, result);
			return result;
		}
	}

	@Override
	public boolean outputFilter(String keyword, String alternative) {
		return checkInput(alternative);
	}

}
