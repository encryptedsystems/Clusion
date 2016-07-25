//***********************************************************************************************//

// This file contains IEX-2Lev implementation. KeyGen, Setup, Token and Test algorithms. 
// We also propose an implementation of a possible filtering mechanism that reduces the storage overhead. 

//***********************************************************************************************//	

package org.crypto.sse;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.ExecutionException;

public class IEX2Lev implements Serializable {


	// Parameter of Disjunctive search
	public static int maxDocumentIDs = 0;
	static double filterParameter = 0.05;
	public static long numberPairs	=0;
	MMGlobal globalMM	=	null;
	MMGlobal[]	localMultiMap	=	null;
	Multimap<String, Integer>	dictionaryForMM	=	null;


	
	public IEX2Lev(MMGlobal globalMM,	MMGlobal[]	localMultiMap,	Multimap<String, Integer>	dictionaryForMM	){
		this.globalMM	=	globalMM;
		this.localMultiMap	=	localMultiMap;
		this.dictionaryForMM	=	dictionaryForMM;
	}

	public MMGlobal getGlobalMM() {
		return globalMM;
	}


	public void setGlobalMM(MMGlobal globalMM) {
		this.globalMM = globalMM;
	}


	public MMGlobal[] getLocalMultiMap() {
		return localMultiMap;
	}


	public void setLocalMultiMap(MMGlobal[] localMultiMap) {
		this.localMultiMap = localMultiMap;
	}


	public Multimap<String, Integer> getDictionaryForMM() {
		return dictionaryForMM;
	}


	public void setDictionaryForMM(Multimap<String, Integer> dictionaryForMM) {
		this.dictionaryForMM = dictionaryForMM;
	}



	//***********************************************************************************************//

	/////////////////////    KeyGen	/////////////////////////////

	//***********************************************************************************************//	


	public static List<byte[]> keyGen(int keySize, String password, String filePathString, int icount) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException{

		List<byte[]> listOfkeys	=	 new ArrayList<byte[]>();


		// Generation of two keys for Secure inverted index
		listOfkeys.add(InvertedIndex.keyGenSI(keySize, password+"secureIndex", filePathString, icount));
		listOfkeys.add(InvertedIndex.keyGenSI(keySize, password+"dictionary", filePathString, icount));

		// Generation of one key for encryption
		listOfkeys.add(SecureSetM.keyGenSM(keySize, password+"encryption", filePathString, icount));

		return listOfkeys;

	}





	//***********************************************************************************************//

	/////////////////////    Setup	/////////////////////////////

	//***********************************************************************************************//	






	public static IEX2Lev setupDISJ(List<byte[]> keys,  Multimap<String, String> lookup, Multimap<String, String> lookup2, int bigBlock, int smallBlock, int dataSize) throws InterruptedException, ExecutionException, IOException{



		//Instantiation of the object that contains Global MM, Local MMs and the dictionary
		MMGlobal[]	localMultiMap	=	new MMGlobal[lookup.keySet().size()];
		Multimap<String, Integer>	dictionaryForMM	=	ArrayListMultimap.create();


		System.out.println("Number of (w, id) pairs "+lookup2.size());

		System.out.println("Number of keywords "+lookup.keySet().size());


		BufferedWriter writer = new BufferedWriter(new FileWriter("logs.txt", true));

		writer.write("\n *********************Stats******* \n");

		writer.write("\n Number of (w, id) pairs "+lookup2.size());
		writer.write("\n Number of keywords "+lookup.keySet().size());

		int counter	=	0;

		//***********************************************************************************************//

		/////////////////////    Computing Filtering Factor	/////////////////////////////

		//***********************************************************************************************//			
		HashMap<Integer,Integer> histogram= new HashMap<Integer,Integer>();
		System.out.println("Number of documents "+ lookup2.keySet().size());
		for (String keyword	:	lookup.keySet()){
			if (histogram.get(lookup.get(keyword).size()) != null){
				int tmp = histogram.get(lookup.get(keyword).size());
				histogram.put(lookup.get(keyword).size(), tmp+1);
			}
			else{
				histogram.put(lookup.get(keyword).size(), 1);
			}

			if (dataSize < lookup.get(keyword).size()){
				dataSize = lookup.get(keyword).size();
			}

		}



		int occurence = 0;
		for (int i=0; i<lookup2.keySet().size()+1; i++){
			if (histogram.get(i) != null){
				occurence =occurence + histogram.get(i)*i;				
			}

			if (occurence > filterParameter *lookup2.size()){
				occurence = i;
				break;
			}
		}

		System.out.println("Value of the filter "+occurence);
		System.out.println("Data size "+dataSize);

		filterParameter = occurence;

		writer.write("\n Value of the filter parameter "+filterParameter);

		//Construction of the global multi-map
		System.out.println("\nBeginning of Global MM creation \n");


		long startTime1 =System.nanoTime();


		IEX2Lev	disj2	=	new IEX2Lev(MMGlobal.constructEMMPar(keys.get(0), lookup, bigBlock, smallBlock, dataSize), localMultiMap, dictionaryForMM);

		long endTime1 =System.nanoTime();

		writer.write("\n Time of MM global setup time #(w, id)/#DB "+(endTime1-startTime1)/lookup2.size());
		writer.close();

		numberPairs	=	numberPairs	+lookup.size();

		//Construction of the local multi-map

		dataSize = dataSize/100;



		for (String keyword	:	lookup.keySet()){

			// Stats for keeping track with the evaluation

			for (int j=0;j<100;j++){

				if (counter == (int) ((j+1)	*	lookup.keySet().size()/100)){
					BufferedWriter writer2 = new BufferedWriter(new FileWriter("temp-logs.txt", true));
					writer2.write("\n Number of local multi-maps created"+ j +" %");
					writer2.close();

					break;
				}
			}

			System.out.println("Number of Keywords processed for the local Multi-Map "+counter);

			//Filter setting optional. For a setup without any filtering set filterParameter to 1

			if (lookup.get(keyword).size() < filterParameter){
				//Stats
				System.out.println("Keyword entrant "+keyword);
				BufferedWriter writer3 = new BufferedWriter(new FileWriter("words-logs.txt", true));
				writer3.write("\n Keyword entrant "+ keyword);
				writer3.close();

				for (int j=0;j<10;j++){

					if (counter == (int) ((j+1)	*	lookup.keySet().size()/10)){	
						System.out.println("Number of total keywords processed equals "+ j +"0 % \n");
						break;
					}
				}

				// First computing V_w. Determine Doc identifiers

				Set<String>  VW	=	new TreeSet<String>();
				for (String idDoc : lookup.get(keyword)){
					VW.addAll(lookup2.get(idDoc));
				}

				Multimap<String, String> secondaryLookup	=	ArrayListMultimap.create();

				// here we are only interested in documents in the intersection between "keyword" and "word"
				for (String word: VW){
					//Filter setting optional. For a setup without any filtering set filterParameter to 1

					if (lookup.get(word).size() < filterParameter){
						Collection<String> l1 = new ArrayList<String>(lookup.get(word));
						Collection<String> l2 = new ArrayList<String>(lookup.get(keyword));
						l1.retainAll(l2);
						secondaryLookup.putAll(word, l1);
					}
				}

				//End of VW construction
				MMGlobal.counter	=0;
				dataSize = (int) filterParameter;
				disj2.getLocalMultiMap()[counter]	=	MMGlobal.constructEMMPar(CryptoPrimitives.generateCmac(keys.get(0),keyword), secondaryLookup, bigBlock, smallBlock, dataSize);
				byte[] key3	=	CryptoPrimitives.generateCmac(keys.get(1), 3	+keyword);
				numberPairs	=numberPairs +secondaryLookup.size();
				dictionaryForMM.put(new String(key3), counter);

			}
			counter++;

		}

		disj2.setDictionaryForMM(dictionaryForMM);
		return disj2;



	}


	//***********************************************************************************************//

	/////////////////////    Token Generation	/////////////////////////////

	//***********************************************************************************************//	

	public static List<TokenDIS> genToken(List<byte[]> listOfkeys, List<String> search) throws UnsupportedEncodingException{
		List<TokenDIS> token	=	new ArrayList<TokenDIS>();

		for (int i=0; i<search.size(); i++){

			List<String> subSearch	=	new ArrayList<String>();
			// Create a temporary list that carry keywords in *order*
			for (int j=i; j<search.size();j++){
				subSearch.add(search.get(j));
			}

			token.add(new TokenDIS(subSearch, listOfkeys));	
		}
		return token;

	}


	//***********************************************************************************************//

	/////////////////////    TEST	/////////////////////////////

	//***********************************************************************************************//	

	public static Set<String> testDIS(List<TokenDIS> token, IEX2Lev disj) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{

		Set<String> finalResult	=	new TreeSet<String>();
		for (int i=0; i<token.size(); 	i++){

			Set<String>	result	=	new HashSet<String>(MMGlobal.testSI(token.get(i).getTokenMMGlobal(), disj.getGlobalMM().getDictionary(), disj.getGlobalMM().getArray()));


			if (!	(result.size()	==	0)){
				List<Integer> temp	=	new ArrayList<Integer>(disj.getDictionaryForMM().get(new String(token.get(i).getTokenDIC())));
				System.out.println(disj.getDictionaryForMM().get(new String(token.get(i).getTokenDIC())));




				if (!(temp.size() == 0)){
					int pos	=	temp.get(0);	

					for (int j=0; j<token.get(i).getTokenMMLocal().size()	; j++){

						Set<String>	temporary	=	new HashSet<String>();
						List<String> tempoList	=	MMGlobal.testSI(token.get(i).getTokenMMLocal().get(j), 
								disj.getLocalMultiMap()[pos].getDictionary(), 
								disj.getLocalMultiMap()[pos].getArray());



						if (!(tempoList == null)){
							temporary	=	new HashSet<String>(MMGlobal.testSI(token.get(i).getTokenMMLocal().get(j), 
									disj.getLocalMultiMap()[pos].getDictionary(), 
									disj.getLocalMultiMap()[pos].getArray()));
						}


						result	=	Sets.difference(result, temporary);
						if (result.isEmpty()){
							break;
						}

					}
				}
				finalResult.addAll(result);
			}
		}

		return finalResult;

	}

}
