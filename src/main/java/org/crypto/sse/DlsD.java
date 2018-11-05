package org.crypto.sse;

import java.io.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Collections;
import com.google.common.collect.Multimaps;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.math.BigInteger;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import java.util.HashMap;


public class DlsD {
	
	//The global state for restructuring
	static int state_global_version = 1;
	
	// A set that stores all labels of the multi-map
	static Collection<String> state_set_labels = Collections.synchronizedSet(new HashSet<String>());
	
	//A set that stores all labels that have been searched for
	static Collection<String> state_set_search = new HashSet<String>();
	
	//An old dictionary that stores the version/count for every label
	static Multimap<String, Integer[]> state_old_DX = Multimaps.synchronizedListMultimap(ArrayListMultimap.<String, Integer[]>create());
	
	//A new dictionary that stores the version/count for every label
	static Multimap<String, Integer[]> state_new_DX = ArrayListMultimap.create(); 	

	//A dictionary that will hold the old encrypted multi-map
	public static Multimap<String, byte[]> old_dictionary = Multimaps.synchronizedListMultimap(ArrayListMultimap.<String, byte[]>create());
	
	//A dictionary that will hold the new encrypted multi-map
	public Multimap<String, byte[]> new_dictionary = ArrayListMultimap.create(); 
	
	//size of the value
	public static int sizeOfFileIdentifer = 48;
	
	//a buffer(stash) used by the user to de-amortize the restructuring. In case
	//the tuple size of a particular keyword is larger than the public parameter, we stash
	//remaining to be added in the next restructuring step
	//This is very important for security reasons
	static List<byte[]> stash_1 = new ArrayList<byte[]>(); 
	static List<byte[]> stash_2 = new ArrayList<byte[]>(); 
	static Multimap<String, byte[]> stash_MM_1 = ArrayListMultimap.create(); 
	static Multimap<String, byte[]> stash_MM_2 = ArrayListMultimap.create(); 
	
	public DlsD (Multimap<String, byte[]> old_dictionary, Multimap<String, byte[]> new_dictionary){
		this.old_dictionary = old_dictionary;
		this.new_dictionary = new_dictionary;
	}
	
	public Multimap<String, byte[]> getOld_dictionary() {
		return old_dictionary;
	}

	public void setOld_dictionary(Multimap<String, byte[]> old_dictionary) {
		this.old_dictionary = old_dictionary;
	}

	public Multimap<String, byte[]> getNew_dictionary() {
		return new_dictionary;
	}

	public void setNew_dictionary(Multimap<String, byte[]> new_dictionary) {
		this.new_dictionary = new_dictionary;
	}
	// ***********************************************************************************************//
	///////////////////// Key Generation /////////////////////////////
	// ***********************************************************************************************//

	public static byte[] keyGen(int keySize, String password, String filePathString, int icount)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		File f = new File(filePathString);
		byte[] salt = null;
		if (f.exists() && !f.isDirectory()) {
			salt = CryptoPrimitives.readAlternateImpl(filePathString);
		} else {
			salt = CryptoPrimitives.randomBytes(keySize/8);
			CryptoPrimitives.write(salt, "salt", "salt");
		}
		byte[] key = CryptoPrimitives.keyGenSetM(password, salt, icount, keySize);
		return key;
	}
	
	// ***********************************************************************************************//
	///////////////////// Setup /////////////////////////////
	// ***********************************************************************************************//
	public static Integer setup(byte[] key1, byte[] key2, String[] listOfKeyword, Multimap<String, String> lookup) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{		
		byte[] randomValue = CryptoPrimitives.randomBytes(16);
		for (String l : listOfKeyword){
			//add the label to the set of labels
			synchronized(state_set_labels) {
				state_set_labels.add(l);
			}
			// initialize temporary counter/version
			int count =1;
			int version = 1;
			//compute the label/values
			for (String v : lookup.get(l)){
				byte[] label = CryptoPrimitives.generateHmac(key1, l+version+count);
				if(v.getBytes().length >= sizeOfFileIdentifer-9) {
         			v = new String( v.getBytes("UTF-8") , 0, sizeOfFileIdentifer-9, "UTF-8");
         		}
				byte[] value = CryptoPrimitives.encryptAES_CTR_String(key2, randomValue, v+"+", sizeOfFileIdentifer);
				count =count+1;
				byte[] ivBytes = new byte[16];
				System.arraycopy(value, 0, ivBytes, 0, ivBytes.length);

				byte add = 1;
				for (int x = ivBytes.length - 1 ; x > -1; x--) {
					if (ivBytes[x]==(byte)255) {
						ivBytes[x] = (byte)(ivBytes[x] + add);
					} else {
						ivBytes[x] = (byte)(ivBytes[x] + add);
						break;
					}
				}
				randomValue = ivBytes;
				synchronized(old_dictionary) { 
					old_dictionary.put(new String(label, "ISO-8859-1"), value);
				}
			}

			synchronized(state_old_DX) { 
				state_old_DX.put(l, new Integer[]{version, count-1});
			}
		}
		return new Integer(1);
	}
	
	// ***********************************************************************************************//
	///////////////////// Setup Parallel /////////////////////////////
	// ***********************************************************************************************//	
	
	public static DlsD constructEMMParGMM(final byte[] key1, final byte[] key2, final Multimap<String, String> lookup) throws InterruptedException, ExecutionException, IOException {
		Multimap<String, byte[]> new_dictionary = ArrayListMultimap.create();
		List<String> listOfKeyword = new ArrayList<String>(lookup.keySet());
		int threads = 0;
		if (Runtime.getRuntime().availableProcessors() > listOfKeyword.size()) {
			threads = listOfKeyword.size();
		} else {
			threads = Runtime.getRuntime().availableProcessors();
		}

		ExecutorService service = Executors.newFixedThreadPool(threads);
		ArrayList<String[]> inputs = new ArrayList<String[]>(threads);

		for (int i = 0; i < threads; i++) {
			String[] tmp;
			if (i == threads - 1) {
				tmp = new String[listOfKeyword.size() / threads + listOfKeyword.size() % threads];
				for (int j = 0; j < listOfKeyword.size() / threads + listOfKeyword.size() % threads; j++) {
					tmp[j] = listOfKeyword.get((listOfKeyword.size() / threads) * i + j);
				}
			} else {
				tmp = new String[listOfKeyword.size() / threads];
				for (int j = 0; j < listOfKeyword.size() / threads; j++) {

					tmp[j] = listOfKeyword.get((listOfKeyword.size() / threads) * i + j);
				}
			}
			inputs.add(i, tmp);
		}
		System.out.println("End of Partitionning  \n");

		List<Future<Integer>> futures = new ArrayList<Future<Integer>>();
		for (final String[] input : inputs) {
			Callable<Integer> callable = new Callable<Integer>() {
				public Integer call() throws Exception {
					Integer output = setup(key1,key2, input, lookup);
					return output;
				}
			};
			futures.add(service.submit(callable));
		}

		service.shutdown();
		for (int findi = futures.size()-1; findi > -1; findi--) {
			Future<Integer> future = futures.get(findi);
			Integer lala = future.get();
		}
		state_global_version ++;
		return new DlsD(old_dictionary, new_dictionary);
	}
	// ***********************************************************************************************//
	///////////////////// Search Token generation /////////////////////
	// ***********************************************************************************************//

	public static String[][] token(byte[] key1, byte[]  key2, String keyword) throws UnsupportedEncodingException {
		int new_version = 0;
		int new_counter = 0;
		int old_version = 0;
		int old_counter = 0;
		
		if (state_new_DX.containsKey(keyword)){
			Integer[] temp = state_new_DX.get(keyword).iterator().next();
			new_version = temp[0];
			new_counter = temp[1];
		}
		if (state_old_DX.containsKey(keyword)){
			Integer[] temp = state_old_DX.get(keyword).iterator().next();
			old_version = temp[0];
			old_counter = temp[1];
		}		
		//adding the searched for kewyord to the set
		//if and only if the label keyword exists in the old dictionary.
		//this to ensure the correctness of the de-amortized restructuring 		
		if (old_counter>0){
			state_set_search.add(keyword);
		}
		
		String[][] stoken = new String[2][];
		String[] temp1 = new String[old_counter];
		String[] temp2 = new String[new_counter];

		for (int i = 1; i <= old_counter;i++){
			temp1[i-1] = new String(CryptoPrimitives.generateHmac(key1, keyword+old_version+i), "ISO-8859-1");
		}
		stoken[0] = temp1;
		for (int i = 1; i <= new_counter;i++){
			temp2[i-1] = new String(CryptoPrimitives.generateHmac(key1, keyword+new_version+i), "ISO-8859-1");
		}
		stoken[1] = temp2;
		return stoken;
	}	
	
	// ***********************************************************************************************//
	///////////////////// Query (test alg) /////////////////////////////
	// ***********************************************************************************************//	
	
	public static List<byte[]> query(String[][] stoken, DlsD emm){
		List<byte[]> result = new ArrayList<byte[]>();
		for (int i = 0; i < stoken[0].length ; i++){
			result.add(emm.getOld_dictionary().get(stoken[0][i]).iterator().next());
		}
		for (int i = 0; i < stoken[1].length ; i++){
			result.add(emm.getNew_dictionary().get(stoken[1][i]).iterator().next());
		}
		return result;
	}	
	
	// ***********************************************************************************************//
	///////////////////// Decryption Algorithm /////////////////////////////
	// ***********************************************************************************************//
	public static List<String> resolve(byte[] key2, List<byte[]> list) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		List<String> result = new ArrayList<String>();
		List<String> suppress = new ArrayList<String>();
		for (byte[] ct : list) {
			String decr = new String(CryptoPrimitives.decryptAES_CTR_String(ct, key2)).split("\t\t\t")[0];
			if (decr.substring(decr.length()-1, decr.length()).equals("+")){
				result.add(decr.substring(0, decr.length()-1));
			}
			else{
				suppress.add(decr.substring(0, decr.length()-1));
			}
		}
		for (String decr : suppress){
			if (result.contains(decr)){
				result.remove(decr);
			}
		}
		return result;
	}
	
	// ***********************************************************************************************//
	///////////////////// Token Update /////////////////////////////
	// ***********************************************************************************************//
	public static byte[][] tokenUp(byte[] key1, byte[] key2, String label, String value, String op) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		byte[][] tokenUp = new byte[2][];	
		int version =0;
		int counter =0;
		if (!state_set_labels.contains(label)){
			version = state_global_version;
			counter =1;
			state_set_labels.add(label);
			state_new_DX.put(label, new Integer[]{version, counter});
		}
		else{
			if (state_new_DX.containsKey(label)){
				Integer[] temp = state_new_DX.get(label).iterator().next();
				version = temp[0];
				counter = temp[1];
				counter ++;
				state_new_DX.removeAll(label);
				state_new_DX.put(label, new Integer[]{state_global_version, counter});
			}
			else{
				counter = 1;
				version = state_global_version;
				state_new_DX.put(label, new Integer[]{version, counter});
			}
		}
		tokenUp[0] = CryptoPrimitives.generateHmac(key1, label+version+counter);
		tokenUp[1] = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16), value+op, sizeOfFileIdentifer);
		return tokenUp;
	}
	
	
	// ***********************************************************************************************//
	///////////////////// Update /////////////////////////////
	// ***********************************************************************************************//

	public static void update(byte[][] tokenUp, DlsD emm) throws UnsupportedEncodingException {
		Multimap<String, byte[]> temp = emm.getNew_dictionary();
		temp.put(new String(tokenUp[0] ,"ISO-8859-1"), tokenUp[1]);
		emm.setNew_dictionary(temp);
	}
	
	// ***********************************************************************************************//
	///////////////////// Restruct /////////////////////////////
	// ***********************************************************************************************//
	public static void deamortized_restruct(byte[] key1, byte[] key2, DlsD emm, int public_parameter) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		//Client computation 
		// computation of a sample of a Bernoulli distribution
		byte[] rnd  = CryptoPrimitives.randomBytes(4);
		int sample = 0;
		double parameter = ((double)state_set_search.size()) / state_old_DX.keySet().size();
		if (CryptoPrimitives.getLongFromByte(rnd, 32)/Math.pow(2, 31) < parameter){
			sample++;
		}

		//Filling the stashes with at least public_parameter sub-tokens
		if ((sample == 1) && (state_set_search.size() >0) && (stash_MM_1.keySet().size() < public_parameter)){
			String label = state_set_search.iterator().next();
			state_set_search.remove(label);
			int old_version = 0;
			int old_counter = 0;
			
			if (state_old_DX.containsKey(label)){
				Integer[] temp = state_old_DX.get(label).iterator().next();
				old_version = temp[0];
				old_counter = temp[1];
			}
			//remove label from old dictionary
			state_old_DX.removeAll(label);
			for (int i = 1; i <= old_counter;i++){
				String l = new String(CryptoPrimitives.generateHmac(key1, label+old_version+i), "ISO-8859-1");
				stash_1.add(emm.getOld_dictionary().get(l).iterator().next());
			}
			//compute the Result set to insert
			List<String> result = new ArrayList<String>();
			result = DlsD.resolve(key2, stash_1);
			stash_1 = new ArrayList<byte[]>(); 
			// setting the counter / version right
			int new_version = 0;
			int new_counter = 0;
			if (state_new_DX.containsKey(label)){
				Integer[] temp = state_new_DX.get(label).iterator().next();
				new_version = temp[0];
				new_counter = temp[1];
			}
			else{
				new_counter=0;
				new_version = state_global_version;
			}
			//Calculating the new label/values to insert in the new dictionary
			for (String val : result){
				new_counter ++;
				String l = new String(CryptoPrimitives.generateHmac(key1, label+new_version+new_counter), "ISO-8859-1");
				byte[] v = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16), val+"+", sizeOfFileIdentifer);
				stash_MM_1.put(l, v);
			}
			// Updating the new state DX
			state_new_DX.removeAll(label);
			state_new_DX.put(label, new Integer[]{state_global_version,new_counter});

		}
		else if ((stash_MM_2.size()<public_parameter) && (state_old_DX.keySet().size()>0)){
			while ((stash_MM_2.size() < public_parameter) && (state_old_DX.keySet().size() >0)){
				//select a label that has not been searched for
				//TO DO , we need to randomize the order of the state_old_DX.keySet()
				// as well as the search set
				String label="";
				Iterator<String> it = state_old_DX.keySet().iterator();
				while(it.hasNext()){
					label = it.next();
					if (!state_set_search.contains(label)){
						break;
					}
				}
				//getting the counters
				Integer[] temp = state_old_DX.get(label).iterator().next();
				int old_version = temp[0];
				int old_counter = temp[1];
				//updating the state
				state_old_DX.removeAll(label);
				if (old_counter > 1){
					state_old_DX.put(label, new Integer[]{old_version,old_counter-1});
				}
				String l = new String(CryptoPrimitives.generateHmac(key1, label+old_version+old_counter), "ISO-8859-1");
				String value = new String(CryptoPrimitives.decryptAES_CTR_String(emm.getOld_dictionary().get(l).iterator().next(), key2)).split("\t\t\t")[0];	
				// setting the counter / version right
				int new_version = 0;
				int new_counter = 0;
				if (state_new_DX.containsKey(label)){
					temp = state_new_DX.get(label).iterator().next();
					new_version = temp[0];
					new_counter = temp[1];
					new_counter++;
					String l2 = new String(CryptoPrimitives.generateHmac(key1, label+new_version+new_counter), "ISO-8859-1");
					byte[] v = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16), value, sizeOfFileIdentifer);
					stash_MM_2.put(l2, v);	
					// updating the new state DX
					state_new_DX.removeAll(label);
					state_new_DX.put(label, new Integer[]{state_global_version,new_counter});
				}
				else{
					new_counter=1;
					new_version = state_global_version;
					String l2 = new String(CryptoPrimitives.generateHmac(key1, label+new_version+new_counter), "ISO-8859-1");
					byte[] v = CryptoPrimitives.encryptAES_CTR_String(key2, CryptoPrimitives.randomBytes(16), value, sizeOfFileIdentifer);
					stash_MM_2.put(l2, v);	
					// updating the new state DX
					state_new_DX.removeAll(label);
					state_new_DX.put(label, new Integer[]{state_global_version,new_counter});
				}	
			}
		}

		int counter=0;
		if ((sample == 1)  && (stash_MM_1.keySet().size()>0)){
			while ((counter<public_parameter) && (stash_MM_1.keySet().size()>0)){
				Multimap<String, byte[]> temp = emm.getNew_dictionary();
				String label = stash_MM_1.keySet().iterator().next();
				byte[] value = stash_MM_1.get(label).iterator().next();
				stash_MM_1.removeAll(label);
				temp.put(label, value);		
				emm.setNew_dictionary(temp);
				counter++;
			}
		}
		else if ((sample == 0) && (stash_MM_2.keySet().size()>0)){
			while ((counter<public_parameter) && (stash_MM_2.keySet().size()>0)){
				Multimap<String, byte[]> temp = emm.getNew_dictionary();
				String label = stash_MM_2.keySet().iterator().next();
				byte[] value = stash_MM_2.get(label).iterator().next();
				stash_MM_2.removeAll(label);
				temp.put(label, value);		
				emm.setNew_dictionary(temp);
				counter++;
			}	
		}
		if ((state_old_DX.keySet().size() == 0) && (stash_MM_1.keySet().size()==0) && (stash_MM_2.keySet().size()==0)){
			state_global_version ++;
			state_old_DX = state_new_DX;
			state_new_DX = ArrayListMultimap.create(); 
			Multimap<String, byte[]> temp = emm.getNew_dictionary();
			emm.setOld_dictionary(temp);
			Multimap<String, byte[]> temp2 = ArrayListMultimap.create();
			emm.setNew_dictionary(temp2);
		}	
	}	
}