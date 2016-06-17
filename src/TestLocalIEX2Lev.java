//***********************************************************************************************//

// This file contains the step-by-step local benchmarking of the IEX-2Lev. The encrypted data structure remains in the RAM.
// This file also gathers stats useful to give some insights about the scheme implementation
// One needs to wait until the complete creation of the encrypted data structures of IEX-2Lev in order to issue queries.
// Queries need to be in the form of CNF. Follow on-line instructions
//***********************************************************************************************//


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.common.collect.Sets;

import net.sourceforge.sizeof.SizeOf;

public class TestLocalIEX2Lev {


	public static void main(String[] args) throws Exception{

		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		System.out.println("Enter your password :");

		String pass	=	keyRead.readLine();

		List<byte[]> listSK	=	IEX2Lev.keyGen(256, pass, "salt/salt", 100);

		long startTime =System.nanoTime();


		BufferedWriter writer = new BufferedWriter(new FileWriter("logs.txt", true));


		System.out.println("Enter the relative path name of the folder that contains the files to make searchable");

		String pathName	=	keyRead.readLine();


		//Creation of different files based on selectivity 
		// Selectivity was computed in an inclusive way. All files that include x(i+1) include necessarily xi
		// This is used for benchmarking and can be taken out of the code

		ArrayList<File> listOfFile=new ArrayList<File>();
		TextProc.listf(pathName, listOfFile); 


		int select = 0;


		for (File file:listOfFile){
			PrintWriter pw = null;
			if (select<listOfFile.size()){
				try {
					FileWriter fw = new FileWriter(file, true);
					pw = new PrintWriter(fw);

					if (select<10){
						pw.println("iex10");
					}

					if (select<50){

						pw.println("iex50");

					}

					if (select<100){
						pw.println("iex100");

					}

					if (select<500){
						pw.println("iex500");

					}

					if (select<1000){
						pw.println("iex1000");

					}

					if (select<listOfFile.size()){
						pw.println("iex10000");

					}

				} catch (IOException e) {
					e.printStackTrace();
				} finally {
					if (pw != null) {
						pw.close();
					}
				}	

				select =select+1;	
			}
		}


		TextProc.TextProc(false, pathName);

		int bigBlock	=	1000;
		int smallBlock	=	100;



		long startTime2 = System.nanoTime();


		IEX2Lev	disj	=	IEX2Lev.setupDISJ(listSK, TextExtractPar.lp1, TextExtractPar.lp2, bigBlock, smallBlock, 0);



		long endTime2   = System.nanoTime();
		long totalTime2 = endTime2 - startTime2;

		//Writing logs


		System.out.println("\n*****************************************************************");
		System.out.println("\n\t\tSTATS");
		System.out.println("\n*****************************************************************");

		//System.out.println("\nNumber of keywords "+TextExtractPar.totalNumberKeywords);
		System.out.println("\nNumber of (w, id) pairs "+TextExtractPar.lp2.size());
		writer.write("\n Number of (w, id) pairs "+TextExtractPar.lp2.size());


		System.out.println("\nTotal number of stored (w, Id) including in local MM : "+IEX2Lev.numberPairs);
		writer.write("\n Total number of stored (w, Id) including in local MM : "+IEX2Lev.numberPairs);


		System.out.println("\nTime elapsed per (w, Id) in ns: "+totalTime2/IEX2Lev.numberPairs);
		writer.write("\n Time elapsed per (w, Id) in ns: "+totalTime2/IEX2Lev.numberPairs);


		System.out.println("\nTotal Time elapsed for the entire construction in seconds: "+totalTime2/1000000000);
		writer.write("\n Total Time elapsed for the entire construction in seconds: "+totalTime2/1000000000);

		System.out.println("\nRelative Time elapsed per (w, Id) in ns: "+totalTime2/TextExtractPar.lp1.size());
		writer.write("\n Relative Time elapsed per (w, Id) in ns: "+totalTime2/TextExtractPar.lp1.size());

		// The two commented commands are used to compute the size of the encrypted Local multi-maps and global multi-maps

		//System.out.println("\nSize of the Structure LMM: "+ SizeOf.humanReadable(SizeOf.deepSizeOf(disj.getLocalMultiMap())));
		//System.out.println("\nSize of the Structure MMg: "+ SizeOf.humanReadable(SizeOf.deepSizeOf(disj.getGlobalMM())));
		writer.close();


		while (true){

			// Boolean queries

			System.out.println("How many disjunctions? ");
			int numDisjunctions = Integer.parseInt(keyRead.readLine());

			// Storing the CNF form 
			String[][] bool = new String[numDisjunctions][];
			for (int i=0; i<numDisjunctions; i++){
				System.out.println("Enter the keywords of the disjunctions ");
				bool[i]	=	keyRead.readLine().split(" ");
			}



			// Generate the IEX token
			List<String> searchBol	=	new ArrayList<String>();
			for (int i=0; i<bool[0].length; i++){
				searchBol.add(bool[0][i]);
			}

			for (int g=0; g<50;g++){

				// Generation of stream file to measure size of the token

				long startTime3 =System.nanoTime();

				System.out.println(searchBol);

				Set<String> tmpBol = IEX2Lev.testDIS(IEX2Lev.genToken(listSK, searchBol),disj);


				File file = null;
				ObjectOutputStream oos = null;
				if (g==0){
					file =  new File("token.ser") ;
					oos =  new ObjectOutputStream(new FileOutputStream(file)) ;	

					oos.writeObject(IEX2Lev.genToken(listSK, searchBol));

				}

				System.out.println(tmpBol);

				for (int i=1; i<numDisjunctions; i++ ){
					Set<String> finalResult = new HashSet<String>();
					for (int k=0; k<bool[0].length;k++){
						List<String> searchTMP	=	new ArrayList<String>();
						searchTMP.add(bool[0][k]);
						for (int r=0; r< bool[i].length; r++){
							searchTMP.add(bool[i][r]);
						}

						List<TokenDIS> tokenTMP	=	IEX2Lev.genToken(listSK, searchTMP);
						if (g==0){
							oos.writeObject(tokenTMP);
						}
						Set<String>	result	=	new HashSet<String>(MMGlobal.testSI(tokenTMP.get(0).getTokenMMGlobal(), disj.getGlobalMM().getDictionary(), disj.getGlobalMM().getArray()));



						if (!	(tmpBol.size()	==	0)){
							List<Integer> temp	=	new ArrayList<Integer>(disj.getDictionaryForMM().get(new String(tokenTMP.get(0).getTokenDIC())));

							if (!(temp.size() == 0)){ 
								int pos	=	temp.get(0);

								for (int j=0; j<tokenTMP.get(0).getTokenMMLocal().size()	; j++){

									Set<String>	temporary	=	new HashSet<String>();
									List<String> tempoList	=	MMGlobal.testSI(tokenTMP.get(0).getTokenMMLocal().get(j), 
											disj.getLocalMultiMap()[pos].getDictionary(), 
											disj.getLocalMultiMap()[pos].getArray());



									if (!(tempoList == null)){
										temporary	=	new HashSet<String>(MMGlobal.testSI(tokenTMP.get(0).getTokenMMLocal().get(j), 
												disj.getLocalMultiMap()[pos].getDictionary(), 
												disj.getLocalMultiMap()[pos].getArray()));
									}


									finalResult.addAll(temporary);

									if (tmpBol.isEmpty()){
										break;
									}

								}
							}


						}
					}
					tmpBol.retainAll(finalResult);

				}						
				long endTime3   = System.nanoTime();
				long totalTime3 = endTime3 - startTime3;

				System.out.println("\nTime elapsed for the query in ns: "+totalTime3);


				BufferedWriter writer2 = new BufferedWriter(new FileWriter("logs.txt", true));
				writer2.write("\n Queries: Time elapsed for the query in ns: "+totalTime3);
				writer2.close();			
			}
		}



	}






}
