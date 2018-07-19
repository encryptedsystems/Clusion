package org.crypto.sse.fuzzy;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.crypto.sse.fuzzy.Fuzzy;

import com.swabunga.spell.engine.SpellDictionaryHashMap;
import com.swabunga.spell.engine.Word;
import com.swabunga.spell.event.SpellCheckEvent;
import com.swabunga.spell.event.SpellCheckListener;
import com.swabunga.spell.event.SpellChecker;

/**
 * A basic spell checker using Jazzy.
 * 
 * @author Ryan Estes
 */
public class JazzySpellChecker implements SpellCheckListener {

	private SpellChecker spellChecker;
	private List<String> misspelledWords;

	public static SpellDictionaryHashMap dictionaryHashMap;

	static {
		File dict = new File(Fuzzy.DICTIONARY_FILE);
		try {
			dictionaryHashMap = new SpellDictionaryHashMap(dict);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public JazzySpellChecker() {

		misspelledWords = new ArrayList<String>();
		spellChecker = new SpellChecker(dictionaryHashMap);
		spellChecker.addSpellCheckListener(this);
	}

	public List<String> getSuggestions(String misspelledWord) {

		@SuppressWarnings("unchecked")
		List<Word> elements = spellChecker.getSuggestions(misspelledWord, 0);
		List<String> suggestions = new ArrayList<String>();
		for (Word suggestion : elements) {
			suggestions.add(suggestion.getWord());
		}

		return suggestions;
	}

	@Override
	public void spellingError(SpellCheckEvent event) {
		event.ignoreWord(true);
		misspelledWords.add(event.getInvalidWord());
	}
}