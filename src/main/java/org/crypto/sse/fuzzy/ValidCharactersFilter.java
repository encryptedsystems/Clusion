package org.crypto.sse.fuzzy;

/**
 * Filters words by checking to see if a word contains only letters
 * in a whitelist or if it contains no words in a blacklist. Default
 * behavior is to use the whitelist containing all 26 uppercase and
 * lowercase letters.
 * 
 * Use {@link #useWhitelist(String)} or {@link #useBlacklist(String)} to
 * define different behavior.
 * 
 * @author Ryan Estes
 */
public class ValidCharactersFilter extends IFilter{

	private boolean whitelist = true;
	private String list = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

	/**
	 * Sets filter to whitelist mode using a specified whitelist.
	 * 
	 * @param validCharacters whitelist
	 * @return this Filter after applying new whitelist
	 */
	public ValidCharactersFilter useWhitelist(String validCharacters) {
		whitelist = true;
		list = validCharacters;
		return this;
	}
	
	/**
	 * Sets filter to blacklist mode using a specified blacklist.
	 * 
	 * @param invalidCharacters blacklist
	 * @return this Filter after applying new blacklist
	 */
	public ValidCharactersFilter useBlacklist(String invalidCharacters) {
		whitelist = false;
		list = invalidCharacters;
		return this;
	}
	
	@Override
	protected boolean inputFilter(String keyword) {
		
		String test = whitelist ? keyword : list;
		String search = whitelist ? list : keyword;
		
		for (char c : test.toCharArray()) {
			if (whitelist ^ search.contains(""+c)) {
				return false;
			}
		}
		return true;
	}

	@Override
	protected boolean outputFilter(String keyword, String alternative) {
		return inputFilter(alternative);
	}

}
