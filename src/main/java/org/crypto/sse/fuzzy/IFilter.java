package org.crypto.sse.fuzzy;

/**
 * Determines whether or not a keyword should be fuzzed by an
 * {@link IFuzzingScheme) or whether an alternative produced by
 * it should be used.
 * 
 * @author Ryan Estes
 * @see {@link Fuzzy}
 */
public abstract class IFilter {
	
	private boolean invert = false;

	/**
	 * {@link #checkInput(String)} and {@link #checkOutput(String, String)}
	 * will return the the opposite response after calling this.
	 * 
	 * @return this Filter after inverting it.
	 */
	public IFilter invert() {
		invert = !invert;
		return this;
	}
	
	/**
	 * Tests a keyword in this filter.
	 * 
	 * @param keyword
	 * @return True if the keyword is accepted by the filter
	 */
	public boolean checkInput(String keyword) {
		return invert ^ inputFilter(keyword);
	}

	/**
	 * Tests whether an alternative to a keyword passes this filter. May
	 * use the keyword it was derived from.
	 * 
	 * @param keyword Only used if this filter needs it
	 * @param alternative
	 * @return True if this alternative is accepted by the filter
	 */
	public boolean checkOutput(String keyword, String alternative) {
		return invert ^ outputFilter(keyword, alternative);
	}
	
	protected abstract boolean inputFilter(String keyword);
	protected abstract boolean outputFilter(String keyword, String alternative);
	
}
