//***********************************************************************************************//

// This file contains IEX-ZMF implementation. KeyGen, Setup, Token and Test algorithms. 
// We also propose an implementation of a possible filtering mechanism that reduces the storage overhead. 

//***********************************************************************************************//	

package org.crypto.sse;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.*;



public class IEXZMF implements Serializable{


	public static int numberOfBF	= 0;
	public static List<SecureSetMFormat> bloomFilterList	=	new ArrayList<SecureSetMFormat>();
	public static HashMap<String, SecureSetMFormat> bloomFilterMap = new HashMap<String, SecureSetMFormat>();
	public static HashMap<String, List<String>> bloomFilterStart = new HashMap<String, List<String>>();

	//***********************************************************************************************//

	/////////////////////    KeyGen	/////////////////////////////

	//***********************************************************************************************//	


	public static List<byte[]> keyGen(int keySize, String password, String filePathString, int icount) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException{

		List<byte[]> listOfkeys	=	 new ArrayList<byte[]>();

		// Generation of the key for Secure Set membership
		listOfkeys.add(SecureSetM.keyGenSM(keySize*3, password+"setM", filePathString, icount));

		// Generation of two keys for Secure inverted index
		listOfkeys.add(InvertedIndex.keyGenSI(keySize, password+"secureIndex1", filePathString, icount));
		listOfkeys.add(InvertedIndex.keyGenSI(keySize, password+"secureIndex2", filePathString, icount));

		// Generation of one key for encryption
		listOfkeys.add(SecureSetM.keyGenSM(keySize, password+"encryption", filePathString, icount));

		return listOfkeys;

	}




	//***********************************************************************************************//

	/////////////////////    Setup for non-partitionning setting	/////////////////////////////

	//***********************************************************************************************//	


	public static void setup(ObjectOutputStream output, List<byte[]> listOfkeys, String pwd, int maxLengthOfMask, int falsePosRate) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeySpecException, IOException, InterruptedException, ExecutionException{

		//no partitionning flag	equals false


		TextProc.TextProc(false, pwd);

		System.out.println("\n Beginning of Secure Set Membership construction \n");

		System.out.println("Number of extracted keywords "+TextExtractPar.lp1.keySet().size());
		System.out.println("Size of the inverted index (leakage N) "+TextExtractPar.lp1.size());


		constructBFPar(new ArrayList(TextExtractPar.lp1.keySet()),listOfkeys.get(0), listOfkeys.get(1), maxLengthOfMask,falsePosRate);

		// Encryption of files and update the encrypted identifiers in the second lookup
		// This commented code below can be used to encrypt files and send them directly to the outsourced server

		/*int counterFile	=	0;	
		ArrayList<File> listOfFile	=	new ArrayList<File>();

		TextProc.listf(pwd, listOfFile); 
		Multimap<String, String> encryptedIdToRealId	=	ArrayListMultimap.create();

		System.out.println("\n Beginning of encrypted file outsourcing \n");


		for (File file :listOfFile){		
			CryptoPrimitives.encryptAES_CTR_Socket(output, "EncryptedFiles/", Integer.toString(counterFile), pwd, file.getName(), listOfkeys.get(3), CryptoPrimitives.randomBytes(16));
			encryptedIdToRealId.put(file.getName(), Integer.toString(counterFile));
			counterFile++;
		}*/

		// Replace all documents identifiers with the corresponding encrypted file id



		// Construction by Cash et al. Crypto 2013 is slower compared to the one by Cash et al. NDSS'14
		//InvertedIndex.constructEMMPar(listOfkeys.get(1), listOfkeys.get(2), listOfkeys.get(3), TextExtractPar.lp1, encryptedIdToRealId);	


	}


	//***********************************************************************************************//

	/////////////////////    GenToken	/////////////////////////////

	//***********************************************************************************************/



	public static List<Token> genToken(List<byte[]> listOfkeys, List<String> search, int falsePosRate , int maxLengthOfMask) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		List<Token> token	=	new ArrayList<Token>();

		for (int i=0; i<search.size(); i++){

			List<String> subSearch	=	new ArrayList<String>();
			// Create a temporary list that carry keywords in *order*
			for (int j=i; j<search.size();j++){
				subSearch.add(search.get(j));
			}

			token.add(new Token(subSearch, listOfkeys, maxLengthOfMask, falsePosRate));	
		}
		return token;

	}


	//***********************************************************************************************//

	/////////////////////    Test Phase	/////////////////////////////

	//***********************************************************************************************/

	public static List<byte[]> test(List<Token> token, List<List<Record>> secureIndex, int bucketSize, int falsePosRate) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		List<byte[]> result	=	new ArrayList<byte[]>();



		for (int i=0; i<token.size(); i++ ){
			List<InvertedIndexResultFormat> resultTMP = InvertedIndex.testSI(token.get(i).getTokenSI1(), token.get(i).getTokenSI2(), secureIndex, bucketSize);



			for (int j=0; j<resultTMP.size(); j++){

				if (i<token.size()-1){


					// Decode first the BF identifier
					String bFIDPadded	=	new String(resultTMP.get(j).getBloomFilterId());

					String bFID	=	"";
					boolean fl	=true;

					for (int k=0; k<bFIDPadded.length(); k++){
						if (bFIDPadded.charAt(k) !='0' || fl==false){
							bFID	=	bFID + bFIDPadded.charAt(k);
							fl	=false;
						}
					}

					if (bFID.equals("")){
						bFID	=	bFID	+"0";
					}


					// endOf decoding the BF id


					// Reading the BF identifier and de-serialization phase


					boolean[] secureSetM = null;
					try{
						InputStream file = new FileInputStream("/home/tarik/workspace/GSSE/BF/"+bFID);
						InputStream buffer = new BufferedInputStream(file);
						ObjectInput input = new ObjectInputStream (buffer);
						secureSetM = (boolean[]) input.readObject();

					}
					catch(ClassNotFoundException ex){
						ex.printStackTrace();
					}
					// End of reading the BF

					// Checking all corresponding tokenSM against the bloom filter

					boolean flag	=	true;
					List<boolean[]> listOfbloomFilter	=	new ArrayList<boolean[]>();
					listOfbloomFilter.add(secureSetM);
					int counter =0;
					while (flag){
						if (SecureSetM.testSM(listOfbloomFilter, token.get(i).getTokenSM().get(counter), falsePosRate)[0]	== true){
							flag = false;
						}
						else if (counter == token.get(i).getTokenSM().size()-1){
							break;
						}
						counter++;
					}

					if (flag == true){
						result.add(resultTMP.get(j).getEncryptedID());
					}

				}

				else{
					result.add(resultTMP.get(j).getEncryptedID());
				}
			}


		}


		return result;

	}

	//***********************************************************************************************//

	/////////////////////    Test Local Phase	/////////////////////////////

	//***********************************************************************************************/

	public static List<String> testLocal(List<Token> token, IEX2Lev disj, int bucketSize, int falsePosRate) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		List<String> result	=	new ArrayList<String>();



		for (int i=0; i<token.size(); i++ ){
			List<String>	resultTMP	=	MMGlobal.testSI(token.get(i).getTokenMMGlobal(), disj.getGlobalMM().getDictionary(), disj.getGlobalMM().getArray());




			List<boolean[]> listOfbloomFilter	=	new ArrayList<boolean[]>();


			if (i<token.size()-1){
				List<String> bFIDPaddeds	=	bloomFilterStart.get(new String(token.get(i).getTokenSI1()));

				for (int j=0; j<resultTMP.size(); j++){

					// Decode first the BF identifier


					int bFID = Integer.parseInt(bFIDPaddeds.get(j));
					// endOf decoding the BF id

					// Checking all corresponding tokenSM against the bloom filter

					listOfbloomFilter.add(bloomFilterMap.get(Integer.toString(bFID)).getSecureSetM());

				}

			}

			for (int j=0; j<resultTMP.size(); j++){


				if (i<token.size()-1){

					boolean flag	=	true;

					int counter =0;
					while (flag){

						if (SecureSetM.testSM(listOfbloomFilter, token.get(i).getTokenSM().get(counter), falsePosRate)[j]	== true){
							flag = false;
						}
						else if (counter == token.get(i).getTokenSM().size()-1){
							break;
						}
						counter++;
					}

					if (flag == true){
						result.add(resultTMP.get(j));
					}
				}

				else{
					result.add(resultTMP.get(j));
				}
			}


		}


		return result;

	}
	//***********************************************************************************************//

	/////////////////////    Decryption of identifiers Client side	/////////////////////////////

	//***********************************************************************************************/

	public static List<String> decryptMatch(List<byte[]> encryptedID, byte[] keyENC) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		List<String> result = new ArrayList<String>();

		for (int i=0; i<encryptedID.size(); i++){
			String tmp = new String (CryptoPrimitives.decryptAES_CTR_String(encryptedID.get(i), keyENC)).split("\t\t\t")[0];
			result.add(tmp);
		}

		return result;
	}



	public static void constructBFPar(List<String> listOfKeyword, final byte[] keySM, final byte[] keyInvInd, final int maxLengthOfMask, final int falsePosRate)
			throws InterruptedException, ExecutionException, IOException {


		long startTime =System.nanoTime();

		int threads =0;
		if (Runtime.getRuntime().availableProcessors()>listOfKeyword.size()){
			threads = listOfKeyword.size();
		}
		else{
			threads = Runtime.getRuntime().availableProcessors();
		}


		ExecutorService service = Executors.newFixedThreadPool(threads);
		ArrayList<String[]> inputs=new ArrayList<String[]>(threads);



		for (int i=0;i<threads;i++){
			String[] tmp;
			if (i	==	threads-1){
				tmp=new String[listOfKeyword.size()/threads	+	listOfKeyword.size() % threads];
				for (int j=0;j<listOfKeyword.size()/threads	+	listOfKeyword.size() % threads;j++){
					tmp[j]=listOfKeyword.get((listOfKeyword.size()/threads)	*	i	+	j);
				}
			}
			else{
				tmp=new String[listOfKeyword.size()/threads];
				for (int j=0;j<listOfKeyword.size()/threads;j++){

					tmp[j]=listOfKeyword.get((listOfKeyword.size()/threads)	*	i	+	j);
				}
			}
			inputs.add(i, tmp);
		}


		List<Future<List<SecureSetMFormat> >> futures = new ArrayList<Future<List<SecureSetMFormat> >>();
		for (final String[] input : inputs) {

			Callable<List<SecureSetMFormat> > callable = new Callable<List<SecureSetMFormat> >() {
				public List<SecureSetMFormat>  call() throws Exception {

					List<SecureSetMFormat>  output =	secureSetMPar(input,keySM, keyInvInd, maxLengthOfMask, falsePosRate);   

					return output;
				}
			};
			futures.add(service.submit(callable));
		}

		service.shutdown();



		// We have created the HashMap instead of the list for in memory benchmarking
		for (Future<List<SecureSetMFormat> > future : futures) {
			bloomFilterList.addAll(future.get());

		}
		long endTime   = System.nanoTime();
		long totalTime = endTime - startTime;
		System.out.println("\nTime in (ns) for one BFX in average: "+totalTime/TextExtractPar.lp1.size());

	}



	public static List<SecureSetMFormat> secureSetMPar(String[] input, byte[] keySM, byte[] keyInvInd, int maxLengthOfMask, int falsePosRate) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{
		List<SecureSetMFormat> result	=	new ArrayList<SecureSetMFormat>();

		for (String keyword	: input){


			System.out.println("keyword being processed to issue matryoshka filters: "+ keyword);

			List<boolean[]> secureSetM = SecureSetM.setupSetM(keySM, keyword, TextExtractPar.lp2, TextExtractPar.lp1, maxLengthOfMask, falsePosRate);			
			for (int i=0; i<secureSetM.size(); i++){
				result.add(new SecureSetMFormat(secureSetM.get(i), Integer.toString(numberOfBF)));
				bloomFilterMap.put(Integer.toString(numberOfBF), new SecureSetMFormat(secureSetM.get(i), Integer.toString(numberOfBF)));
				if (i==0){
					bloomFilterStart.put(new String(InvertedIndex.genTokSI(keyInvInd, keyword)), new ArrayList<String>());
					bloomFilterStart.get(new String(InvertedIndex.genTokSI(keyInvInd, keyword))).add(Integer.toString(numberOfBF));
				}
				else{
					bloomFilterStart.get(new String(InvertedIndex.genTokSI(keyInvInd, keyword))).add(Integer.toString(numberOfBF));
				}

				System.out.println("Matryoshka filter number: "+ numberOfBF);
				numberOfBF++;

			}		
		}



		return result;
	}



}
