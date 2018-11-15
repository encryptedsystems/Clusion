package org.crypto.sse;

import java.io.BufferedReader;
import java.io.*;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.io.PrintWriter;
public class TestLocalDlsD {
	
	 
	public static void main(String[] args) throws Exception {
		Printer.addPrinter(new Printer(Printer.LEVEL.EXTRA));
		
		BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Enter your password :");
		String pass = keyRead.readLine();
		byte[] sk = DlsD.keyGen(256, pass, "salt/salt", 100);
		
		byte[] key1 = new byte[sk.length / 2];
		byte[] key2 = new byte[sk.length / 2];
		System.arraycopy(sk, 0 , key1, 0, sk.length / 2);
		System.arraycopy(sk, sk.length / 2, key2, 0, sk.length / 2);
		System.out.println("Enter the relative path name of the folder that contains the files to make searchable");
		String pathName = keyRead.readLine();
		ArrayList<File> listOfFile = new ArrayList<File>();

		TextProc.listf(pathName, listOfFile);
		TextProc.TextProc(false, pathName);
		System.out.println("\nBeginning of Encrypted Multi-map creation \n");
		DlsD emm = DlsD.constructEMMParGMM(key1, key2, TextExtractPar.lp1);
        System.out.println("size of dict pre-search (w, id) pairs" + emm.getOld_dictionary().size()+ " Unique keywords "+TextExtractPar.lp1.keySet().size()+"\n");

		while (true) {
			System.out.println("\n\n\t NEW ROUND and Global State ="+DlsD.state_global_version+"\n\n");
			System.out.println("\nEnter the keyword to search for:");
			String keyword = keyRead.readLine();
			
			//generation of the search token
			String[][] stoken = DlsD.token(key1, key2, keyword);
			System.out.println(DlsD.resolve(key2, DlsD.query(stoken, emm)));
			
			// update phase
			System.out.println("Enter the keyword to add/delete:");
			String label = keyRead.readLine();
			System.out.println("Enter the doc ID to add/delete:");
			String value  = keyRead.readLine();
			System.out.println("Enter the operation (+/-):");
			String op  = keyRead.readLine();
			byte[][] tokenUp = DlsD.tokenUp(key1, key2, label, value, op);
			DlsD.update(tokenUp, emm);
			
			//restructuring
			int parameter = 3;
			emm.deamortized_restruct(key1, key2, emm, parameter);

			System.out.println("To exit , enter Y else enter N");
			String exit  = keyRead.readLine();
			if (exit.equals("Y")) {
				break;
			}
		}
	}
}
