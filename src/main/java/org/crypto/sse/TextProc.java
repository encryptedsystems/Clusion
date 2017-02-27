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

/////////////////////    Text Parsing with a new partitioning technique 	/////////////////////////////

//***********************************************************************************************//
package org.crypto.sse;

import com.google.common.collect.Multimap;

import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;

public class TextProc {

	public TextProc(int i) {

	}

	public static void TextProc(boolean flag, String pwd)
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException {

		int counter = 0;
		ArrayList<File> listOfFile = new ArrayList<File>();

		// ***********************************************************************************************//

		///////////////////// TEXT PARSING and Inverted Index CREATION
		///////////////////// /////////////////////////////

		// ***********************************************************************************************//

		System.out.println("\n Beginning of text extraction \n");

		listf(pwd, listOfFile);
		try {
			TextExtractPar.extractTextPar(listOfFile);
		} catch (InterruptedException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		} catch (ExecutionException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}

		// ***********************************************************************************************//

		///////////////////// Partitioning /////////////////////////////

		// ***********************************************************************************************//
		if (flag) {
			Multimap<Integer, String> partitions = Partition.partitioning(TextExtractPar.lp1);
		}

	}

	/*
	 * This method gets all files from a directory. These files, will be
	 * processed later on to get all the keywords and create an inverted index
	 * structure
	 */
	public static void listf(String directoryName, ArrayList<File> files) {
		File directory = new File(directoryName);

		// get all the files from a directory
		File[] fList = directory.listFiles();
		for (File file : fList) {
			if (file.isFile()) {
				files.add(file);
			} else if (file.isDirectory()) {
				listf(file.getAbsolutePath(), files);
			}
		}
	}

}
