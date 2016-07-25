//***********************************************************************************************//

// This file contains most cryptographic primitives : AES in CTR mode for file and string encryption, HMAC, CMAC-AES and HCB1 online cipher. The file also contains some other
// tools for bytes manipulation
//***********************************************************************************************//

package org.crypto.sse;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.ThreadedSeedGenerator;

public class CryptoPrimitives {

	private CryptoPrimitives(){}


	//***********************************************************************************************//

	/////////////////////    KeyGen	return a raw key based on PBE PKCS12/////////////////////////////
	/////////////////////	 almost taken from org.bouncycastle.jce.provider.test.PBETest 
	//		check also doc in http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory/////////////////////////////
	//***********************************************************************************************//	

	public static byte[] keyGenSetM(String pass, byte[] salt, int icount, int keySize) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException{

		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, icount, keySize);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
		return secret.getEncoded();
	}



	//***********************************************************************************************//

	/////////////////////    CMAC-AES generation	/////////////////////////////

	//***********************************************************************************************//	


	public static byte[] generateCmac(byte[] key, String msg)
			throws UnsupportedEncodingException
			{
		CMac cmac = new CMac(new AESFastEngine());
		byte[] data = msg.getBytes("UTF-8");
		byte[] output = new byte[cmac.getMacSize()];

		cmac.init(new KeyParameter(key));
		cmac.reset();	 
		cmac.update(data, 0, data.length);
		cmac.doFinal(output, 0);
		return output;
			}


	//***********************************************************************************************//

	/////////////////////    HMAC-SHA256 generation	/////////////////////////////

	//***********************************************************************************************//	

	public static byte[] generateHmac(byte[] key, String msg)
			throws UnsupportedEncodingException
			{

		HMac hmac=new HMac(new SHA256Digest());
		byte[] result=new byte[hmac.getMacSize()];
		byte[] msgAry=msg.getBytes("UTF-8");
		hmac.init(new KeyParameter(key));
		hmac.reset();
		hmac.update(msgAry,0,msgAry.length);
		hmac.doFinal(result,0);
		return result;
			}


	//***********************************************************************************************//

	/////////////////////    HMAC-SHA512generation	/////////////////////////////

	//***********************************************************************************************//	

	public static byte[] generateHmac512(byte[] key, String msg)
			throws UnsupportedEncodingException
			{

		HMac hmac=new HMac(new SHA512Digest());
		byte[] result=new byte[hmac.getMacSize()];
		byte[] msgAry=msg.getBytes("UTF-8");
		hmac.init(new KeyParameter(key));
		hmac.reset();
		hmac.update(msgAry,0,msgAry.length);
		hmac.doFinal(result,0);
		return result;
			}

	//***********************************************************************************************//

	/////////////////////    Salt generation/RandomBytes: it is generated just once and it is not necessary to keep it secret /////////////////////////////

	//can also be used for random bit generation
	//***********************************************************************************************//	


	public static byte[] randomBytes(int sizeOfSalt){
		byte[] salt=new byte[sizeOfSalt];
		ThreadedSeedGenerator thread = new ThreadedSeedGenerator();
		SecureRandom random = new SecureRandom();
		random.setSeed(thread.generateSeed(20, true));
		random.nextBytes(salt);     
		return salt;
	}





	//***********************************************************************************************//

	/////////////////////    AES-CTR encryption of a String /////////////////////////////

	//***********************************************************************************************//	


	public static byte[] encryptAES_CTR_String(byte[] keyBytes, byte[] ivBytes, String identifier, int sizeOfFileName) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());  

		// Concatenate the title with the text. The title should be at most "sizeOfFileName" characters including 3 characters marking the end of it
		identifier	=	identifier	+"\t\t\t";
		byte[] input =	concat(identifier.getBytes(), new byte[sizeOfFileName	-	identifier.getBytes().length]);

		//byte[] input	=	concat(input1	,	input0);
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		ByteArrayInputStream bIn = new ByteArrayInputStream(input);
		CipherInputStream cIn = new CipherInputStream(bIn, cipher);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		int ch;
		while ((ch = cIn.read()) >= 0) {
			bOut.write(ch);
		}			    
		byte[] cipherText =	concat(ivBytes,	bOut.toByteArray());

		return cipherText;

	}


	//***********************************************************************************************//

	/////////////////////    AES-CTR Decryption of String /////////////////////////////

	//***********************************************************************************************//	


	public static byte[] decryptAES_CTR_String(byte[] input, byte[] keyBytes) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());  
		//byte[] input	=	readAlternateImpl(folder	+	fileName);



		byte[] ivBytes = new byte[16];
		byte[] cipherText = new byte[input.length	-	16];


		System.arraycopy(input, 0, ivBytes, 0, ivBytes.length);
		System.arraycopy(input, ivBytes.length, cipherText, 0, cipherText.length);

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");


		//Initalization of the Cipher
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);



		ByteArrayOutputStream	bOut = new ByteArrayOutputStream();
		CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);		    

		cOut.write(cipherText);
		cOut.close();

		return bOut.toByteArray();
	}



	//***********************************************************************************************//

	/////////////////////    AES-CTR encryption (Designed for sending encrypted files directly to the outsourced servers)/////////////////////////////

	//***********************************************************************************************//	


	public static void encryptAES_CTR_Socket(ObjectOutputStream out, String folderName,	String outputFileName, String folderInput, String inputFileName, byte[] keyBytes, byte[] ivBytes) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());  
		byte[] input0	=	readAlternateImpl(folderInput+inputFileName);

		// Concatenate the title with the text. The title should be at most 42 characters with 2 characters marking the end of it

		String endOfTitle	=	"\t";

		inputFileName	=	inputFileName	+	endOfTitle;
		byte[] input1 =	concat(inputFileName.getBytes(), new byte[42	-	inputFileName.getBytes().length]);


		byte[] input	=	concat(input1	,	input0);
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		ByteArrayInputStream bIn = new ByteArrayInputStream(input);
		CipherInputStream cIn = new CipherInputStream(bIn, cipher);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		int ch;
		while ((ch = cIn.read()) >= 0) {
			bOut.write(ch);
		}


		byte[] cipherText =	concat(ivBytes,	bOut.toByteArray());



		// Send the outputfile name
		out.writeObject(outputFileName);
		out.flush();

		// Send the ciphertext
		out.writeObject(cipherText);
		out.flush();

	}
















	//***********************************************************************************************//

	/////////////////////    AES-CTR encryption /////////////////////////////

	//***********************************************************************************************//	


	public static void encryptAES_CTR(String folderName,	String outputFileName, String folderInput, String inputFileName, byte[] keyBytes, byte[] ivBytes) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());  
		byte[] input0	=	readAlternateImpl(folderInput+inputFileName);

		// Concatenate the title with the text. The title should be at most 42 characters with 2 characters marking the end of it

		String endOfTitle	=	"\t";

		inputFileName	=	inputFileName	+	endOfTitle;
		byte[] input1 =	concat(inputFileName.getBytes(), new byte[42	-	inputFileName.getBytes().length]);


		byte[] input	=	concat(input1	,	input0);
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		ByteArrayInputStream bIn = new ByteArrayInputStream(input);
		CipherInputStream cIn = new CipherInputStream(bIn, cipher);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		int ch;
		while ((ch = cIn.read()) >= 0) {
			bOut.write(ch);
		}


		byte[] cipherText =	concat(ivBytes,	bOut.toByteArray());


		write(cipherText,	outputFileName,	folderName);



	}




	//***********************************************************************************************//

	/////////////////////    AES-CTR Decryption /////////////////////////////

	//***********************************************************************************************//	


	public static void decryptAES_CTR(String folderOUT,	byte[] input, byte[] keyBytes) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());  




		byte[] ivBytes = new byte[16];
		byte[] cipherText = new byte[input.length	-	16];


		System.arraycopy(input, 0, ivBytes, 0, ivBytes.length);
		System.arraycopy(input, ivBytes.length, cipherText, 0, cipherText.length);

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");


		//Initalization of the Cipher
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);



		ByteArrayOutputStream	bOut = new ByteArrayOutputStream();
		CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);		    

		cOut.write(cipherText);
		cOut.close();

		//Splitting the title from the plaintext

		byte[] title = new byte[42];
		byte[] plaintext = new byte[bOut.toByteArray().length	-	42];
		System.arraycopy(bOut.toByteArray(), 0, title, 0, title.length);
		System.arraycopy(bOut.toByteArray(), title.length, plaintext, 0, plaintext.length);

		String filename	=	new String (title).split("\t")[0];


		write(plaintext, filename,	folderOUT);
	}

	//***********************************************************************************************//

	/////////////////////   Generic Read and Write Byte to files /////////////////////////////

	//***********************************************************************************************//	




	public static void write(byte[] aInput, String aOutputFileName, String dirName){
		// creation of a directory if it is not created
		//sanitizing the aOutputFileName



		(new File(dirName)).mkdir();
		try {
			OutputStream output = null;
			try {
				output = new BufferedOutputStream(new FileOutputStream(dirName+"/"+aOutputFileName));
				output.write(aInput);
			}
			finally {
				output.close();
			}
		}
		catch(FileNotFoundException ex){
			System.out.println("File not found.");
		}
		catch(IOException ex){
			System.out.println(ex);
		}
	}

	//Read
	public static byte[] readAlternateImpl(String aInputFileName){
		File file = new File(aInputFileName);
		byte[] result = null;
		try {
			InputStream input =  new BufferedInputStream(new FileInputStream(file));
			result = readAndClose(input);
		}
		catch (FileNotFoundException ex){
			System.out.println(ex);
		}
		return result;
	}

	//Read
	private static byte[] readAndClose(InputStream aInput){
		byte[] bucket = new byte[32*1024]; 
		ByteArrayOutputStream result = null; 
		try  {
			try {

				result = new ByteArrayOutputStream(bucket.length);
				int bytesRead = 0;
				while(bytesRead != -1){
					bytesRead = aInput.read(bucket);
					if(bytesRead > 0){
						result.write(bucket, 0, bytesRead);
					}
				}
			}
			finally {
				aInput.close();
			}
		}
		catch (IOException ex){
			System.out.println(ex);
		}
		return result.toByteArray();
	}

	//***********************************************************************************************//

	/////////////////////   Transform an array of bytes to an integer based on a specific number of bits needed
	// Note that these functionalities can be further enhanced for better performances /////////////////////////////

	//***********************************************************************************************//	



	public static int getBit(byte[] data, int pos) {
		int posByte = pos/8; 
		int posBit = pos%8;
		byte valByte = data[posByte];
		int valInt = valByte>>(8-(posBit+1)) & 0x0001;
		return valInt;
	}

	public static int[] getBits(byte[] data, int numberOfBits){
		int[] bitArray=new int[numberOfBits];
		for (int j=0;j<numberOfBits;j++){
			bitArray[j]=getBit(data,j);
		}
		return bitArray;
	}

	public static int getIntFromByte(byte[] byteArray, int numberOfBits){
		int result=0;
		int[] bitArray=getBits(byteArray,numberOfBits);

		for (int i=0;i<numberOfBits;i++){
			result=result+ (int) bitArray[i]*(int)Math.pow(2, i);
		}
		return result;
	}

	public static long getLongFromByte(byte[] byteArray, int numberOfBits){
		long result	=	0;
		int[] bitArray=getBits(byteArray,numberOfBits);

		for (int i=0;i<numberOfBits;i++){
			result=result+ bitArray[i]*(int)Math.pow(2, i);
		}
		return result;
	}


	public static boolean[] intToBoolean(int number, int numberOfBits){
		boolean[] pathNumber = new boolean[numberOfBits];

		//represent the number in a binary vector
		String s=Integer.toString(number,2);
		String s1 ="";
		for (int i=0; i<s.length(); i++){
			s1 = s1+ s.charAt(s.length()-i-1);
		}

		//pad the binary vector by zeros to have the same length as the number of bits requested
		while (s1.length()<numberOfBits){
			s1=s1+"0";
		}

		//convert the string s to an integer representation of bits (specially in a boolean array)
		for (int i =0;i<numberOfBits;i++){
			pathNumber[i]=	(s1.charAt(i) != '0');
		}
		return pathNumber;					
	}


	public static String booleanToString(boolean[] message){
		String result	="";
		for (int i=0; i<message.length;i++){

			if (message[i]==true){
				result	=	result+1;

			}
			else{
				result	=	result+0;

			}
		}

		return result;
	}


	public static byte[] booleanToBytes(boolean[] input) {
		byte[] byteArray = new byte[input.length / 8];
		for (int entry = 0; entry < byteArray.length; entry++) {
			for (int bit = 0; bit < 8; bit++) {
				if (input[entry * 8 + bit]) {
					byteArray[entry] |= (128 >> bit);
				}
			}
		}

		return byteArray;
	} 


	public static boolean[] bytesToBoolean(byte[] bytes) {
		boolean[] bits = new boolean[bytes.length * 8];
		for (int i = 0; i < bytes.length * 8; i++) {
			if ((bytes[i / 8] & (1 << (7 - (i % 8)))) > 0)
				bits[i] = true;
		}
		return bits;
	}
	//***********************************************************************************************//

	/////////////////////   byte array concatenation /////////////////////////////

	//***********************************************************************************************//	


	public static byte[] concat(byte[] a, byte[] b) {
		int aLen = a.length;
		int bLen = b.length;
		byte[] c= new byte[aLen+bLen];
		System.arraycopy(a, 0, c, 0, aLen);
		System.arraycopy(b, 0, c, aLen, bLen);
		return c;
	}

	//***********************************************************************************************//

	/////////////////////   Circular hashing /////////////////////////////

	//***********************************************************************************************//	


	public static boolean[] circular(byte[] key, boolean[] message) throws UnsupportedEncodingException{
		boolean result[]	=	new boolean[message.length];
		String tmpResult	=	"";
		String tmpMes		=	"";

		for (int i=message.length-1	;	i>=0 ;	i--){


			tmpMes		=	tmpMes	+String.valueOf(message[i]);

			byte[] cmac=CryptoPrimitives.generateCmac(key, tmpResult+tmpMes);
			tmpResult	=	tmpResult	+ String.valueOf(CryptoPrimitives.getBit(cmac, 0)!=0);
			result[i]	=	(CryptoPrimitives.getBit(cmac, 0)!=0);	

		}

		return result;
	}

	public static boolean circularXOR(boolean[] message) {
		boolean result = false;
		for (int i=0; i<message.length; i++){
			result	=	result ^ message[i];
		}
		System.out.print(" RESULT \t"+result);
		return result;
	}


	//***********************************************************************************************//

	/////////////////////   Online Cipher Implementation of HCBC1 of Bellare et al. with AES-CTR block cipher
	////////////////////							and hash function SHA-256	(http://eprint.iacr.org/2007/197)/////////////////////////////

	//***********************************************************************************************//	


	public static boolean[][] onlineCipher(byte[] keyHash, byte[] keyEnc, boolean[] plaintext) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());  

		//Block extension using Block expansion function
		int blockSize = 128;
		boolean[][] blocks = new boolean[plaintext.length][blockSize];

		// le premier block contient le vecteur d�ntialization
		boolean[][] tmpResults1 = new boolean[plaintext.length+1][blockSize];
		tmpResults1[0] = new boolean[blockSize];;

		// temporary results 2
		boolean[][] tmpResults2 = new boolean[plaintext.length][blockSize];

		// final results
		boolean[][] results = new boolean[plaintext.length][blockSize];


		for (int i=0; i<plaintext.length; i++){
			//we have one bit and we add 127 bits to it
			blocks[i][0] = plaintext[i]; 
			for (int j=1; j<blockSize;j++){
				blocks[i][j] = false;
			}
		}


		SecretKeySpec key = new SecretKeySpec(keyEnc, "AES");

		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

		cipher.init(Cipher.ENCRYPT_MODE, key);
		for (int i=0; i<plaintext.length; i++ ){
			byte[] hmac	=	CryptoPrimitives.generateHmac(keyHash, CryptoPrimitives.booleanToString(tmpResults1[i]));

			for (int j=0; j<blockSize;j++){
				tmpResults2[i][j] = (CryptoPrimitives.getBit(hmac, j)!=0)   ^   blocks[i][j];
			}



			ByteArrayInputStream bIn = new ByteArrayInputStream(CryptoPrimitives.booleanToBytes(tmpResults2[i]));

			CipherInputStream cIn = new CipherInputStream(bIn, cipher);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			int ch;
			while ((ch = cIn.read()) >= 0) {
				bOut.write(ch);
			}			    
			results[i] =	CryptoPrimitives.bytesToBoolean(bOut.toByteArray());
			tmpResults1[i+1] =	results[i];

		}


		return results;

	}
}






















