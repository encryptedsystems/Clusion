/*Tokenizer based on Lucene. This is the core of the code and depends
 * of the input Analyzer. Standard, stop words stripping off or Snowball Porter implementations
 * can be used as an Analyzer. This part of code, given a string of keywords,
 * tokenizes them as a list of String.
 */

package org.crypto.sse;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;

public final class Tokenizer {

	private Tokenizer() {}

	public static List<String> tokenizeString(Analyzer analyzer, String string) {
		List<String> result = new ArrayList<String>();
		try {
			TokenStream stream  = analyzer.tokenStream(null, new StringReader(string));
			stream.reset();
			while (stream.incrementToken()) {
				result.add(stream.getAttribute(CharTermAttribute.class).toString());
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return result;
	}

}