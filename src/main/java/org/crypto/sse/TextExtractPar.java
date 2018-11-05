/** * Copyright (C) 2016 Tarik Moataz
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//***********************************************************************************************//

/////////////////////    This file contains the generation of the database DB, i.e., building a plaintext look-up table that associates every keyword to the set fo documents identifiers	/////////////////////////////

/*TEXT extractor parses the content of documents into raw text
 * the output of this parser is given to Lucene for tokenization.
 * The tokenization used is a standard one where stop words are eliminated.
 * A more sophisticated tokenization is possible such as Porter stemming algorithm.
 * This part can be modified to handle a more specific user grammar.
 * The actual parser handles the following extensions:
- .txt, html etc
- Microsoft documents .doc and .docx, EXCEEL sheet .xls and Powerpoint presentation .ppt
- Pdf files  .pdf
- All media files such as pictures and videos are not parsed and only the title of the media file is taken as input gif, jpeg, .wmv, .mpeg, .mp4
*/
//***********************************************************************************************//	

package org.crypto.sse;

import com.google.common.base.Charsets;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.io.Files;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.en.EnglishAnalyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.analysis.util.CharArraySet;
import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.pdfparser.PDFParser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.util.PDFTextStripper;
import org.apache.poi.hwpf.extractor.WordExtractor;
import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.openxml4j.exceptions.OpenXML4JException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.poifs.filesystem.NPOIFSFileSystem;
import org.apache.poi.xslf.extractor.XSLFPowerPointExtractor;
import org.apache.poi.xssf.extractor.XSSFExcelExtractor;
import org.apache.poi.xwpf.extractor.XWPFWordExtractor;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.xmlbeans.XmlException;

import java.io.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;

public class TextExtractPar implements Serializable {

	public static int lengthStrings = 0;
	public static int totalNumberKeywords = 0;
	public static int maxTupleSize = 0;
	public static int threshold = 100;

	// lookup1 stores a plaintext inverted index of the dataset, i.e., the
	// association between the keyword and documents that contain the keyword

	Multimap<String, String> lookup1 = ArrayListMultimap.create();
	public static Multimap<String, String> lp1 = ArrayListMultimap.create();

	// lookup2 stores the document identifier (title) and the keywords contained
	// in this document

	Multimap<String, String> lookup2 = ArrayListMultimap.create();
	public static Multimap<String, String> lp2 = ArrayListMultimap.create();

	static int counter = 0;

	public TextExtractPar(Multimap<String, String> lookup, Multimap<String, String> lookup2) {
		this.lookup1 = lookup;
		this.lookup2 = lookup2;
	}

	public Multimap<String, String> getL1() {
		return this.lookup1;
	}

	public Multimap<String, String> getL2() {
		return this.lookup2;
	}

	public static void extractTextPar(ArrayList<File> listOfFile)
			throws InterruptedException, ExecutionException, IOException {

		int threads = 0;
		if (Runtime.getRuntime().availableProcessors() > listOfFile.size()) {
			threads = listOfFile.size();
		} else {
			threads = Runtime.getRuntime().availableProcessors();
		}

		ExecutorService service = Executors.newFixedThreadPool(threads);
		ArrayList<File[]> inputs = new ArrayList<File[]>(threads);

		System.out.println("Number of Threads " + threads);

		for (int i = 0; i < threads; i++) {
			File[] tmp;
			if (i == threads - 1) {
				tmp = new File[listOfFile.size() / threads + listOfFile.size() % threads];
				for (int j = 0; j < listOfFile.size() / threads + listOfFile.size() % threads; j++) {
					tmp[j] = listOfFile.get((listOfFile.size() / threads) * i + j);
				}
			} else {
				tmp = new File[listOfFile.size() / threads];
				for (int j = 0; j < listOfFile.size() / threads; j++) {

					tmp[j] = listOfFile.get((listOfFile.size() / threads) * i + j);
				}
			}
			inputs.add(i, tmp);
		}

		List<Future<TextExtractPar>> futures = new ArrayList<Future<TextExtractPar>>();
		for (final File[] input : inputs) {
			Callable<TextExtractPar> callable = new Callable<TextExtractPar>() {
				public TextExtractPar call() throws Exception {
					TextExtractPar output = extractOneDoc(input);

					return output;
				}
			};
			futures.add(service.submit(callable));
		}

		service.shutdown();

		for (Future<TextExtractPar> future : futures) {
			Set<String> keywordSet1 = future.get().getL1().keySet();
			Set<String> keywordSet2 = future.get().getL2().keySet();

			for (String key : keywordSet1) {
				lp1.putAll(key, future.get().getL1().get(key));
				if (lp1.get(key).size()>maxTupleSize){
					maxTupleSize= lp1.get(key).size();
				}
			}
			for (String key : keywordSet2) {
				lp2.putAll(key, future.get().getL2().get(key));
			}
		}

	}

	private static TextExtractPar extractOneDoc(File[] listOfFile) throws FileNotFoundException {

		Multimap<String, String> lookup1 = ArrayListMultimap.create();
		Multimap<String, String> lookup2 = ArrayListMultimap.create();

		for (File file : listOfFile) {

			for (int j = 0; j < 100; j++) {

				if (counter == (int) ((j + 1) * listOfFile.length / 100)) {
					System.out.println("Number of files read equals " + j + " %");
					break;
				}
			}

			List<String> lines = new ArrayList<String>();
			counter++;
			FileInputStream fis = new FileInputStream(file);

			// ***********************************************************************************************//

			///////////////////// .docx /////////////////////////////

			// ***********************************************************************************************//

			if (file.getName().endsWith(".docx")) {
				XWPFDocument doc;
				try {

					doc = new XWPFDocument(fis);
					XWPFWordExtractor ex = new XWPFWordExtractor(doc);
					lines.add(ex.getText());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					System.out.println("File not read: " + file.getName());
				}

			}

			// ***********************************************************************************************//

			///////////////////// .pptx /////////////////////////////

			// ***********************************************************************************************//

			else if (file.getName().endsWith(".pptx")) {

				OPCPackage ppt;
				try {

					ppt = OPCPackage.open(fis);
					XSLFPowerPointExtractor xw = new XSLFPowerPointExtractor(ppt);
					lines.add(xw.getText());
				} catch (XmlException e) {
					// TODO Auto-generated catch block
					System.out.println("File not read: " + file.getName());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					System.out.println("File not read: " + file.getName());
				} catch (OpenXML4JException e) {
					System.out.println("File not read: " + file.getName());
				}

			}

			// ***********************************************************************************************//

			///////////////////// .xlsx /////////////////////////////

			// ***********************************************************************************************//

			else if (file.getName().endsWith(".xlsx")) {

				OPCPackage xls;
				try {

					xls = OPCPackage.open(fis);
					XSSFExcelExtractor xe = new XSSFExcelExtractor(xls);
					lines.add(xe.getText());
				} catch (InvalidFormatException e) {
					// TODO Auto-generated catch block
					System.out.println("File not read: " + file.getName());
				} catch (IOException e) {
					System.out.println("File not read: " + file.getName());

				} catch (XmlException e) {
					// TODO Auto-generated catch block
					System.out.println("File not read: " + file.getName());
				} catch (OpenXML4JException e) {
					System.out.println("File not read: " + file.getName());
				}

			}

			// ***********************************************************************************************//

			///////////////////// .doc /////////////////////////////

			// ***********************************************************************************************//

			else if (file.getName().endsWith(".doc")) {

				NPOIFSFileSystem fs;
				try {

					fs = new NPOIFSFileSystem(file);
					WordExtractor extractor = new WordExtractor(fs.getRoot());
					for (String rawText : extractor.getParagraphText()) {
						lines.add(extractor.stripFields(rawText));
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					System.out.println("File not read: " + file.getName());
				}

			}

			// ***********************************************************************************************//

			///////////////////// .pdf /////////////////////////////

			// ***********************************************************************************************//

			else if (file.getName().endsWith(".pdf")) {

				PDFParser parser;
				try {

					parser = new PDFParser(fis);
					parser.parse();
					COSDocument cd = parser.getDocument();
					PDFTextStripper stripper = new PDFTextStripper();
					lines.add(stripper.getText(new PDDocument(cd)));

				} catch (IOException e) {
					// TODO Auto-generated catch block
					System.out.println("File not read: " + file.getName());
				}

			}

			// ***********************************************************************************************//

			///////////////////// Media Files such as gif, jpeg, .wmv, .mpeg,
			///////////////////// .mp4 /////////////////////////////

			// ***********************************************************************************************//

			else if (file.getName().endsWith(".gif") && file.getName().endsWith(".jpeg")
					&& file.getName().endsWith(".wmv") && file.getName().endsWith(".mpeg")
					&& file.getName().endsWith(".mp4")) {

				lines.add(file.getName());

			}

			// ***********************************************************************************************//

			///////////////////// raw text extensions
			///////////////////// /////////////////////////////

			// ***********************************************************************************************//

			else {
				try {

					lines = Files.readLines(file, Charsets.UTF_8);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					System.out.println("File not read: " + file.getName());
				} finally {
					try {
						fis.close();
					} catch (IOException ioex) {
						// omitted.
					}
				}
			}

			// ***********************************************************************************************//

			///////////////////// Begin word extraction
			///////////////////// /////////////////////////////

			// ***********************************************************************************************//

			int temporaryCounter = 0;

			// Filter threshold
			int counterDoc = 0;
			for (int i = 0; i < lines.size(); i++) {

				CharArraySet noise = EnglishAnalyzer.getDefaultStopSet();

				// We are using a standard tokenizer that eliminates the stop
				// words. We can use Stemming tokenizer such Porter
				// A set of English noise keywords is used that will eliminates
				// words such as "the, a, etc"

				Analyzer analyzer = new StandardAnalyzer(noise);
				List<String> token0 = Tokenizer.tokenizeString(analyzer, lines.get(i));
				List<String> token = new ArrayList<String>();
				//removing numbers/1-letter keywords
				for (int j=0; j<token0.size();j++){
					if ((!token0.get(j).matches(".*\\d+.*")
							&&
							(token0.get(j)).length() >1)){
						token.add(token0.get(j));
					}
				}
				
				temporaryCounter = temporaryCounter + token.size();
				
				

				for (int j = 0; j < token.size(); j++) {

					// Avoid counting occurrences of words in the same file
					if (!lookup2.get(file.getName()).contains(token.get(j))) {
						lookup2.put(file.getName(), token.get(j));
					}

					// Avoid counting occurrences of words in the same file
					if (!lookup1.get(token.get(j)).contains(file.getName())) {
						lookup1.put(token.get(j), file.getName());
					}

				}

			}

		}

		// System.out.println(lookup.toString());
		return new TextExtractPar(lookup1, lookup2);

	}

}
