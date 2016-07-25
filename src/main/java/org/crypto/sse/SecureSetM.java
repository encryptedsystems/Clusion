//***********************************************************************************************//
// This file mainly includes the implementation of Matryoshka filter which is a component of the ZMF encrypted multi map. It makes use of Bloom Filters and Online Ciphers
// In particular, we have the four algorithms for ZMF algorithn. This includes KeyGen, setup that builds of Matryoshka filters, a token algorithm and Test algorithm
//***********************************************************************************************//
package org.crypto.sse ;


import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

import com.google.common.collect.Multimap;


public class SecureSetM {


	//The keyHMAC enables the instantiation of the Random ORacle. There is no need for keeping this key secret
	public static final byte[] keyHMAC = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

	private SecureSetM(){

	}


	//***********************************************************************************************//

	/////////////////////    KeyGenSM	/////////////////////////////

	//***********************************************************************************************//	


	public static byte[] keyGenSM(int keySize, String password, String filePathString, int icount) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException{
		File f = new File(filePathString);
		byte[] salt=null;

		if (f.exists() && !f.isDirectory()){
			salt=CryptoPrimitives.readAlternateImpl(filePathString);
		}
		else{
			salt=CryptoPrimitives.randomBytes(8);
			CryptoPrimitives.write(salt, "saltSetM", "salt");

		}

		byte[] key=CryptoPrimitives.keyGenSetM(password, salt, icount, keySize);
		return key;

	}



	//***********************************************************************************************//

	/////////////////////    SetupSM	/////////////////////////////

	//***********************************************************************************************//		

	public static List<boolean[]> setupSetM(byte[] key, String keyword,  Multimap<String, String> documentsComposition,	Multimap<String, String> keywordComposition, int maxLengthOfMask, int falsePosRate) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{


		//Extract all documents' identifiers that are associated to the keyword

		int identifierCounter	=	0; 
		int blockSize = 128;

		List<boolean[]>	listOfBloomFilter	=	new ArrayList<boolean[]>();	
		for (String identifier : keywordComposition.get(keyword)){


			//Creation of ESet
			HashSet<Integer> state=new HashSet<Integer>();

			// Bloom Filter size setup such that it is a multiple of 2. This is 
			// necessary when inserting the result of a hash which has a maximum multiple of 2^x-1

			double arraySize	=	falsePosRate* documentsComposition.get(identifier).size()/Math.log(2);
			int counter=0;
			for (int j=0;j<1000;j++){
				if (arraySize >Math.pow(2, counter)){
					counter++;
				}
				else{
					break;
				}
			}

			//Creation of the Bloom filter
			boolean[] bloomFilter=new boolean[(int) Math.pow(2, counter)];

			//Key of PRF applied to elements

			byte[] keyPRF = new byte[key.length/3];	
			System.arraycopy(key, 0, keyPRF, 0, key.length/3);


			//Key for the online cipher

			byte[] keyOCHash= new byte[key.length/3];
			System.arraycopy(key, key.length/3, keyOCHash, 0, key.length/3);

			byte[] keyOCEnc= new byte[key.length/3];
			System.arraycopy(key, 2*key.length/3, keyOCEnc, 0, key.length/3);



			//Second Step of Secure Set protocol
			for (String word : documentsComposition.get(identifier)){


				//computation of the PRF based on CMAC-AES
				byte[] cmac=CryptoPrimitives.generateCmac(keyPRF, keyword+word);


				//computation of the Random oracle based H1 on HMAC-SHA256
				//computation of the Random oracle based H2 on HMAC-SHA256 

				int position=0;
				boolean mask;

				//False positive rate is the number of hash functions

				for (int i=0;i<falsePosRate;i++){
					byte[] hmac	=	CryptoPrimitives.generateHmac(keyHMAC, i+CryptoPrimitives.booleanToString(CryptoPrimitives.bytesToBoolean(cmac)));

					//We truncate the needed bits from the output of the HMAC to get the bit 1 to counter


					position	=	CryptoPrimitives.getIntFromByte(hmac, maxLengthOfMask);
					if (!state.contains(position)){
						// Transform the position into an array of boolean []
						boolean[] messageBol	=	CryptoPrimitives.intToBoolean(position, maxLengthOfMask);

						boolean[][] results = CryptoPrimitives.onlineCipher(keyOCHash, keyOCEnc, messageBol);

						boolean[] positionFinal = new boolean[counter * blockSize];

						for (int s=0; s< counter; s++){
							System.arraycopy(results[s], 0, positionFinal, s*blockSize, blockSize);
						}
						byte[] hmac2	=	CryptoPrimitives.generateHmac(keyHMAC, identifierCounter+CryptoPrimitives.booleanToString(positionFinal));


						//We truncate the needed bits from the output of the HMAC to get the bit 1 to counter
						mask	=	(CryptoPrimitives.getBit(hmac2, 0)!=0);


						int pos = CryptoPrimitives.getIntFromByte(hmac, counter);
						bloomFilter[pos]=	true	^	mask; 	
						state.add(pos);
					}


				}		
			}


			for (int j=0	;	j<bloomFilter.length	;j++){

				if (!state.contains(j)){
					boolean[] messageBol	=	CryptoPrimitives.intToBoolean(j, maxLengthOfMask);
					boolean[][] results = CryptoPrimitives.onlineCipher(keyOCHash, keyOCEnc, messageBol);
					boolean[] positionFinal = new boolean[counter * blockSize];
					for (int s=0; s< counter; s++){
						System.arraycopy(results[s], 0, positionFinal, s*blockSize, blockSize);
					}

					byte[] hmac3	=	CryptoPrimitives.generateHmac(keyHMAC, identifierCounter+CryptoPrimitives.booleanToString(positionFinal));


					bloomFilter[j]=	false	^	(CryptoPrimitives.getBit(hmac3, 0)!=0); 

				}
			}

			listOfBloomFilter.add(bloomFilter);

			identifierCounter++;

		}



		return listOfBloomFilter;
	}





	//***********************************************************************************************//

	/////////////////////    GenTokSM without partitioning	/////////////////////////////

	//***********************************************************************************************//	
	public static List<String> genTokSM(byte[] key, String keywordONE,  String keywordTWO, int maxLengthOfMask, int falsePosRate) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{

		List<String> token	=	new ArrayList<String>();

		int blockSize =128;

		//Key of PRF applied to elements

		byte[] keyPRF = new byte[key.length/3];	
		System.arraycopy(key, 0, keyPRF, 0, key.length/3);


		//Key for the online cipher

		byte[] keyOCHash= new byte[key.length/3];
		System.arraycopy(key, key.length/3, keyOCHash, 0, key.length/3);

		byte[] keyOCEnc= new byte[key.length/3];
		System.arraycopy(key, 2*key.length/3, keyOCEnc, 0, key.length/3);


		//computation of the PRF based on CMAC-AES
		byte[] cmac=CryptoPrimitives.generateCmac(keyPRF, keywordONE+keywordTWO);


		token.add(CryptoPrimitives.booleanToString(CryptoPrimitives.bytesToBoolean(cmac)));


		int position=0;

		//False positive rate is the number of hash functions

		for (int i=0;i<falsePosRate;i++){
			byte[] hmac	=	CryptoPrimitives.generateHmac(keyHMAC, i+CryptoPrimitives.booleanToString(CryptoPrimitives.bytesToBoolean(cmac)));

			//We truncate the needed bits from the output of the HMAC to get the bit 1 to counter
			position	=	CryptoPrimitives.getIntFromByte(hmac, maxLengthOfMask);

			// Transform the position into an array of boolean []
			boolean[] messageBol	=	CryptoPrimitives.intToBoolean(position, maxLengthOfMask);

			boolean[][] results = CryptoPrimitives.onlineCipher(keyOCHash, keyOCEnc, messageBol);
			boolean[] positionFinal = new boolean[maxLengthOfMask * blockSize];
			for (int s=0; s< maxLengthOfMask; s++){
				System.arraycopy(results[s], 0, positionFinal, s*blockSize, blockSize);
			}

			token.add(CryptoPrimitives.booleanToString(positionFinal));



		}		
		return token;

	}




	//***********************************************************************************************//

	/////////////////////    TestSM without partitioning	/////////////////////////////

	//***********************************************************************************************//	


	public static boolean[]	testSM(List<boolean[]> listOfbloomFilter, List<String> token, int ratePos) throws UnsupportedEncodingException{
		boolean[] result	=	new boolean[listOfbloomFilter.size()];

		// Fetch first the result of the PRF
		String prf	=	token.get(0);
		int blockSize =128;

		// For each Bloom filter compute whether or not the element exists
		int position;
		boolean mask;
		for (int i=0;i<listOfbloomFilter.size();i++){

			String truncatedTok ="";
			for (int j=0; j<ratePos;j++){

				byte[] hmac	=	CryptoPrimitives.generateHmac(keyHMAC, j+prf);

				//We truncate the needed bits from the output of the HMAC to get the bit 1 to counter
				position	=	CryptoPrimitives.getIntFromByte(hmac, (int) (Math.log(listOfbloomFilter.get(i).length)/Math.log(2)));

				//Truncated Circular TOKEN

				truncatedTok	=	token.get(j+1).substring(0, (int) (Math.log(listOfbloomFilter.get(i).length)/Math.log(2))*blockSize);


				byte[] hmac3	=	CryptoPrimitives.generateHmac(keyHMAC, i+truncatedTok);

				mask=	(CryptoPrimitives.getBit(hmac3, 0)!=0); 


				if (listOfbloomFilter.get(i)[position] ^	mask	== true){
					result[i]	=	true;	

				}
				else{
					result[i]	=	false;
					break;
				}
			}

		}

		return result;
	}

}