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


	public TextProc(int i){

	}

	public static void TextProc(boolean flag, String pwd) throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException{

		int counter=0;
		ArrayList<File> listOfFile=new ArrayList<File>();

		//***********************************************************************************************//

		/////////////////////    TEXT PARSING and Inverted Index CREATION	/////////////////////////////

		//***********************************************************************************************//

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


		//***********************************************************************************************//

		/////////////////////    Partitioning	/////////////////////////////

		//***********************************************************************************************//		
		if (flag){
			Multimap<Integer, String> partitions = Partition.partitioning(TextExtractPar.lp1);
		}


	}



	/*This method gets all files from a directory. 
 These files, will be processed later on to get all the keywords and create an inverted index structure	
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