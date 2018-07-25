package org.crypto.sse.fuzzy;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Singleton that provides access to tools which are useful for
 * fuzzing methods that rely on English language.
 * 
 * @author Ryan Estes
 */
public class LanguageTools {
	
	private static LanguageTools instance = new LanguageTools();
	
	final public JazzySpellChecker JAZZY = new JazzySpellChecker();
	final public List<String> DICTIONARY = new ArrayList<String>();
	
	final public String DICTIONARY_FILE = "dictionary.txt";

	private LanguageTools(){
		BufferedReader fileIn;
		
		try {
			fileIn = new BufferedReader(new FileReader(new File(Fuzzy.DICTIONARY_FILE)));
			String line;
			while ((line = fileIn.readLine()) != null) {
				DICTIONARY.add(line);
			}
			fileIn.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Gets the instance of LangaugeTools to use spell checker
	 * or dictionary.
	 * 
	 * @return the instance of LanguageTools
	 */
	public static LanguageTools getInstance() {
		return instance;
	}
}
