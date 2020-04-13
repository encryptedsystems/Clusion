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

// This file contains most cryptographic primitives : AES in CTR mode for file and string encryption, 
// AES with synthetic IV, HMAC, CMAC-AES and HCB1 online cipher. The file also contains some other
// tools for bytes manipulation and some variations of hash functions to be user
//***********************************************************************************************//

package org.crypto.sse;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.ThreadedSeedGenerator;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class CryptoPrimitives {

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private CryptoPrimitives() {
	}

	// ***********************************************************************************************//

	///////////////////// KeyGen return a raw key based on PBE
	///////////////////// PKCS12 mostly taken from
	///////////////////// org.bouncycastle.jce.provider.test.PBETest
	///////////////////// check also doc in
	///////////////////// http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory/////////////////////////////
	// ***********************************************************************************************//

	public static byte[] keyGenSetM(String pass, byte[] salt, int icount, int keySize)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

		// With Java 8, use "PBKDF2WithHmacSHA256/512" instead
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, icount, keySize);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
		return secret.getEncoded();

	}

	// ***********************************************************************************************//

	///////////////////// CMAC-AES generation /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] generateCmac(byte[] key, String msg) throws UnsupportedEncodingException {
		CMac cmac = new CMac(new AESFastEngine());
		byte[] data = msg.getBytes("UTF-8");
		byte[] output = new byte[cmac.getMacSize()];

		cmac.init(new KeyParameter(key));
		cmac.reset();
		cmac.update(data, 0, data.length);
		cmac.doFinal(output, 0);
		return output;
	}

	// ***********************************************************************************************//

	///////////////////// HMAC-SHA256 generation /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] generateHmac(byte[] key, String msg) throws UnsupportedEncodingException {

		HMac hmac = new HMac(new SHA256Digest());
		byte[] result = new byte[hmac.getMacSize()];
		byte[] msgAry = msg.getBytes("UTF-8");
		hmac.init(new KeyParameter(key));
		hmac.reset();
		hmac.update(msgAry, 0, msgAry.length);
		hmac.doFinal(result, 0);
		return result;
	}

	// ***********************************************************************************************//

	///////////////////// HMAC-SHA256 generation (Byte[] input instead of a
	///////////////////// String)/////////////////////////////

	// ***********************************************************************************************//

	public static byte[] generateHmac(byte[] key, byte[] msg) throws UnsupportedEncodingException {

		HMac hmac = new HMac(new SHA256Digest());
		byte[] result = new byte[hmac.getMacSize()];
		hmac.init(new KeyParameter(key));
		hmac.reset();
		hmac.update(msg, 0, msg.length);
		hmac.doFinal(result, 0);
		return result;
	}

	// ***********************************************************************************************//

	///////////////////// HMAC-SHA512generation /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] generateHmac512(byte[] key, String msg) throws UnsupportedEncodingException {

		HMac hmac = new HMac(new SHA512Digest());
		byte[] result = new byte[hmac.getMacSize()];
		byte[] msgAry = msg.getBytes("UTF-8");
		hmac.init(new KeyParameter(key));
		hmac.reset();
		hmac.update(msgAry, 0, msgAry.length);
		hmac.doFinal(result, 0);
		return result;
	}

	// ***********************************************************************************************//

	///////////////////// Salt generation/RandomBytes: it is generated just once
	///////////////////// and it is not necessary to keep it secret
	///////////////////// can also be used for random bit generation
	// ***********************************************************************************************//

	public static byte[] randomBytes(int size) {
		byte[] randomBytes = new byte[size];
		ThreadedSeedGenerator thread = new ThreadedSeedGenerator();
		SecureRandom random = new SecureRandom();
		random.setSeed(thread.generateSeed(20, false));
		random.nextBytes(randomBytes);
		return randomBytes;
	}

	// ***********************************************************************************************//

	///////////////////// Salt generation/RandomBytes: it is generated just once
	///////////////////// and it is not necessary to keep it secret
	///////////////////// can also be used for random bit generation
	// ***********************************************************************************************//

	public static byte[] randomSeed(int size) {
		byte[] seed = new byte[size];
		ThreadedSeedGenerator thread = new ThreadedSeedGenerator();
		seed = thread.generateSeed(size, false);
		return seed;
	}

	// ***********************************************************************************************//

	///////////////////// OTP-like Encryption ///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] OTPEnc(byte[] key, String plaintext) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		
		int randomnessLength =  32;
		// this is determined as well by the output length of the HMAC
		int messageLength = 32;
		
		
		byte[] randomness = randomBytes(32);
		byte[] hmacOutput = generateHmac(key, randomness);
		
				
		// transforming String to Bytes	
		 byte [] plaintextInBytes = plaintext.getBytes("UTF-8");
		
		//XOR operation	
		byte[] xorResult = new byte[32];
		
		int count  =0;
		for (byte  b : hmacOutput) {
			xorResult[count] = (byte) (b ^ plaintextInBytes[count]);
			count++;
		}

        byte[] output = new byte[messageLength + randomnessLength];

        System.arraycopy(xorResult, 0, output, 0, messageLength);
        System.arraycopy(randomness, 0, output, messageLength, randomnessLength);

		return output;
	}

	
	
	
	// ***********************************************************************************************//

	///////////////////// OTP-like Decryption ///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static String OTPDec(byte[] key, byte[] ciphertext) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		
		
		int randomnessLength =  32;
		
		// this is determined as well by the output length of the HMAC
		int messageLength = 32;
		
		
		byte[] xorPart = new byte[messageLength];
		byte[] randomness = new byte[randomnessLength];

		System.arraycopy(ciphertext, 0           , xorPart, 0     , messageLength);
		System.arraycopy(ciphertext, messageLength, randomness, 0     , randomnessLength);
		
		
		//HMAC computation
		byte[] hmacOutput = generateHmac(key, randomness);

	
		byte[] outputInBytes = new byte[32];
		
		int count  =0;
		for (byte  b : hmacOutput) {
			outputInBytes[count] = (byte) (b ^ xorPart[count]);
			count++;
		}
		String output = new String(outputInBytes, "UTF-8");;


		return output;
	}
	
	// ***********************************************************************************************//

	///////////////////// Message authentication+Encryption (Authenticated
	///////////////////// encryption)
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[][] auth_encrypt_AES_HMAC(byte[] keyEnc, byte[] keyHMAC, byte[] ivBytes, String identifier,
			int maxSize) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		byte[][] output = new byte[2][];

		output[1] = encryptAES_CTR_String(keyEnc, ivBytes, identifier, maxSize);
		output[0] = generateHmac(keyHMAC, output[1]);

		return output;
	}
	
	
	// ***********************************************************************************************//

	///////////////////// Message authentication+Decryption (Authenticated
	///////////////////// encryption)
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[][] auth_decrypt_AES_HMAC(byte[] keyEnc, byte[] keyHMAC, byte[][] input)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		byte[][] output = new byte[2][1];
		output[0][0] = '0';
		output[1] = decryptAES_CTR_String(input[1], keyEnc);
		// splitting required for correctness, we can get rid of the delimiter
		// in encryptAES_CTR_String
		// if we use the same string length

		byte[] hmacResult = generateHmac(keyHMAC, input[1]);

		if (Arrays.equals(hmacResult, input[0])) {
			output[0][0] = '1';
		}

		return output;
	}

	// ***********************************************************************************************//

	///////////////////// AES-CTR encryption of a String
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] encryptAES_CTR_String(byte[] keyBytes, byte[] ivBytes, String identifier, int sizeOfFileName)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		// Concatenate the title with the text. The title should be at most
		// "sizeOfFileName" characters including 3 characters marking the end of
		// it
		identifier = identifier + "\t\t\t";
		byte[] input = concat(identifier.getBytes(), new byte[sizeOfFileName - identifier.getBytes().length]);

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
		byte[] cipherText = concat(ivBytes, bOut.toByteArray());

		cIn.close();
		
		return cipherText;

	}

	// ***********************************************************************************************//

	///////////////////// AES-CBC encryption with no padding
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//


	public static byte[] encryptAES_CBC_String(byte[] keyBytes, byte[] ivBytes, String identifier)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {
	    return encryptAES_CBC(keyBytes, ivBytes, identifier.getBytes("UTF-8"));
	}

	public static byte[] encryptAES_CBC(byte[] keyBytes, byte[] ivBytes, byte[] input)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		ByteArrayInputStream bIn = new ByteArrayInputStream(input);
		CipherInputStream cIn = new CipherInputStream(bIn, cipher);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		int ch;
		while ((ch = cIn.read()) >= 0) {
			bOut.write(ch);
		}
		byte[] cipherText = concat(ivBytes, bOut.toByteArray());
		
		cIn.close();

		return cipherText;

	}

	// ***********************************************************************************************//

	///////////////////// AES-CBC Decryption
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] decryptAES_CBC(byte[] input, byte[] keyBytes)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		byte[] ivBytes = new byte[16];

		byte[] cipherText = new byte[input.length - 16];

		System.arraycopy(input, 0, ivBytes, 0, ivBytes.length);
		System.arraycopy(input, ivBytes.length, cipherText, 0, cipherText.length);

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");


		// Initalization of the Cipher
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);

		cOut.write(cipherText);
		cOut.close();

		return bOut.toByteArray();
	}

	// ***********************************************************************************************//

	///////////////////// AES-CTR Decryption of String
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] decryptAES_CTR_String(byte[] input, byte[] keyBytes)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		byte[] ivBytes = new byte[16];

		byte[] cipherText = new byte[input.length - 16];

		System.arraycopy(input, 0, ivBytes, 0, ivBytes.length);
		System.arraycopy(input, ivBytes.length, cipherText, 0, cipherText.length);

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

		// Initalization of the Cipher
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);

		cOut.write(cipherText);
		cOut.close();

		return bOut.toByteArray();
	}

	// ***********************************************************************************************//

	///////////////////// AES-CTR encryption of a String
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] DTE_encryptAES_CTR_String(byte[] encKeyBytes, byte[] PRFKeyBytes, String identifier,
			int sizeOfFileName) throws InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {

		// Title Encoding: Concatenate the title with the text. The title should
		// be at most "sizeOfFileName" characters including 3 characters marking
		// the end of it
		identifier = identifier + "\t\t\t";
		byte[] input = concat(identifier.getBytes(), new byte[sizeOfFileName - identifier.getBytes().length]);

		// Synthetic IV

		byte[] ivBytes = CryptoPrimitives.generateCmac(PRFKeyBytes, identifier);

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec key = new SecretKeySpec(encKeyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		ByteArrayInputStream bIn = new ByteArrayInputStream(input);
		CipherInputStream cIn = new CipherInputStream(bIn, cipher);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		int ch;
		while ((ch = cIn.read()) >= 0) {
			bOut.write(ch);
		}
		byte[] cipherText = concat(ivBytes, bOut.toByteArray());
		
		cIn.close();

		return cipherText;

	}

	// ***********************************************************************************************//

	///////////////////// AES-CTR encryption (Designed for sending encrypted
	///////////////////// files directly to the outsourced
	///////////////////// servers)/////////////////////////////

	// ***********************************************************************************************//

	public static void encryptAES_CTR_Socket(ObjectOutputStream out, String folderName, String outputFileName,
			String folderInput, String inputFileName, byte[] keyBytes, byte[] ivBytes)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {
		byte[] input0 = readAlternateImpl(folderInput + inputFileName);

		// Concatenate the title with the text. The title should be at most 42
		// characters with 2 characters marking the end of it

		String endOfTitle = "\t";

		inputFileName = inputFileName + endOfTitle;
		byte[] input1 = concat(inputFileName.getBytes(), new byte[42 - inputFileName.getBytes().length]);

		byte[] input = concat(input1, input0);
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

		byte[] cipherText = concat(ivBytes, bOut.toByteArray());
		
		cIn.close();

		// Send the outputfile name
		out.writeObject(outputFileName);
		out.flush();

		// Send the ciphertext
		out.writeObject(cipherText);
		out.flush();

	}

	// ***********************************************************************************************//

	///////////////////// AES-CTR encryption /////////////////////////////

	// ***********************************************************************************************//

	public static void encryptAES_CTR(String folderName, String outputFileName, String folderInput,
			String inputFileName, byte[] keyBytes, byte[] ivBytes)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {
		byte[] input0 = readAlternateImpl(folderInput + inputFileName);

		// Concatenate the title with the text. The title should be at most 42
		// characters with 2 characters marking the end of it

		String endOfTitle = "\t";

		inputFileName = inputFileName + endOfTitle;
		byte[] input1 = concat(inputFileName.getBytes(), new byte[42 - inputFileName.getBytes().length]);

		byte[] input = concat(input1, input0);
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

		byte[] cipherText = concat(ivBytes, bOut.toByteArray());
		
		cIn.close();

		write(cipherText, outputFileName, folderName);

	}

	// ***********************************************************************************************//

	///////////////////// AES-CTR Decryption /////////////////////////////

	// ***********************************************************************************************//

	public static void decryptAES_CTR(String folderOUT, byte[] input, byte[] keyBytes)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IOException {

		byte[] ivBytes = new byte[16];
		byte[] cipherText = new byte[input.length - 16];

		System.arraycopy(input, 0, ivBytes, 0, ivBytes.length);
		System.arraycopy(input, ivBytes.length, cipherText, 0, cipherText.length);

		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

		// Initalization of the Cipher
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);

		cOut.write(cipherText);
		cOut.close();

		// Splitting the title from the plaintext

		byte[] title = new byte[42];
		byte[] plaintext = new byte[bOut.toByteArray().length - 42];
		System.arraycopy(bOut.toByteArray(), 0, title, 0, title.length);
		System.arraycopy(bOut.toByteArray(), title.length, plaintext, 0, plaintext.length);

		String filename = new String(title).split("\t")[0];

		write(plaintext, filename, folderOUT);
	}

	// ***********************************************************************************************//

	///////////////////// Online Cipher Implementation of HCBC1 of Bellare et
	///////////////////// al. with AES-CTR block cipher
	//////////////////// and hash function SHA-256
	///////////////////// (http://eprint.iacr.org/2007/197)/////////////////////////////

	// ***********************************************************************************************//

	public static boolean[][] onlineCipher(byte[] keyHash, byte[] keyEnc, boolean[] plaintext) throws IOException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {

		// Block extension using Block expansion function
		int blockSize = 128;
		boolean[][] blocks = new boolean[plaintext.length][blockSize];

		// le premier block contient le vecteur d�ntialization
		boolean[][] tmpResults1 = new boolean[plaintext.length + 1][blockSize];
		tmpResults1[0] = new boolean[blockSize];
		;

		// temporary results 2
		boolean[][] tmpResults2 = new boolean[plaintext.length][blockSize];

		// final results
		boolean[][] results = new boolean[plaintext.length][blockSize];

		for (int i = 0; i < plaintext.length; i++) {
			// we have one bit and we add 127 bits to it
			blocks[i][0] = plaintext[i];
			for (int j = 1; j < blockSize; j++) {
				blocks[i][j] = false;
			}
		}

		SecretKeySpec key = new SecretKeySpec(keyEnc, "AES");

		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

		cipher.init(Cipher.ENCRYPT_MODE, key);
		for (int i = 0; i < plaintext.length; i++) {
			byte[] hmac = CryptoPrimitives.generateHmac(keyHash, CryptoPrimitives.booleanToString(tmpResults1[i]));

			for (int j = 0; j < blockSize; j++) {
				tmpResults2[i][j] = (CryptoPrimitives.getBit(hmac, j) != 0) ^ blocks[i][j];
			}

			ByteArrayInputStream bIn = new ByteArrayInputStream(CryptoPrimitives.booleanToBytes(tmpResults2[i]));

			CipherInputStream cIn = new CipherInputStream(bIn, cipher);

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			int ch;
			while ((ch = cIn.read()) >= 0) {
				bOut.write(ch);
			}
			results[i] = CryptoPrimitives.bytesToBoolean(bOut.toByteArray());
			tmpResults1[i + 1] = results[i];
			
			cIn.close();

		}

		return results;

	}

	// ***********************************************************************************************//

	///////////////////// Enhanced implementation: Online Cipher Implementation
	///////////////////// of HCBC1 of Bellare et al. with AES-CTR block cipher
	//////////////////// and hash function SHA-256
	///////////////////// (http://eprint.iacr.org/2007/197)/////////////////////////////

	// ***********************************************************************************************//

	public static byte[][] onlineCipherOWF(byte[] keyHash, byte[] keyHash2, boolean[] plaintext) throws IOException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {

		// Block extension using Block expansion function (in bytes)
		int blockSize = 32;
		byte[][] blocks = new byte[plaintext.length][blockSize];

		// le premier block contient le vecteur d�ntialization
		byte[][] tmpResults1 = new byte[plaintext.length + 1][blockSize];
		tmpResults1[0] = new byte[blockSize];
		;

		// temporary results 2
		byte[][] tmpResults2 = new byte[plaintext.length][blockSize];

		// final results
		byte[][] results = new byte[plaintext.length][blockSize];

		for (int i = 0; i < plaintext.length; i++) {
			// we have one byte and we pad to 32 bytes
			blocks[i][0] = (byte) (plaintext[i] ? 1 : 0);
			for (int j = 1; j < blockSize; j++) {
				blocks[i][j] = 0;
			}
		}

		for (int i = 0; i < plaintext.length; i++) {

			byte[] hmac = CryptoPrimitives.generateHmac(keyHash, tmpResults1[i]);

			int j = 0;
			for (byte b : hmac)
				tmpResults2[i][j] = (byte) (b ^ blocks[i][j++]);

			results[i] = CryptoPrimitives.generateHmac(keyHash2, tmpResults2[i]);
			tmpResults1[i + 1] = results[i];

		}

		return results;

	}

	// ***********************************************************************************************//

	///////////////////// Generic Read and Write Byte to files
	///////////////////// /////////////////////////////

	// ***********************************************************************************************//

	public static void write(byte[] aInput, String aOutputFileName, String dirName) {
		// creation of a directory if it is not created
		// sanitizing the aOutputFileName

		(new File(dirName)).mkdir();
		try {
			OutputStream output = null;
			try {
				output = new BufferedOutputStream(new FileOutputStream(dirName + "/" + aOutputFileName));
				output.write(aInput);
			} finally {
				output.close();
			}
		} catch (FileNotFoundException ex) {
			Printer.normalln("File not found.");
		} catch (IOException ex) {
			Printer.debugln(""+ex);
		}
	}

	// Read
	public static byte[] readAlternateImpl(String aInputFileName) {
		File file = new File(aInputFileName);
		byte[] result = null;
		try {
			InputStream input = new BufferedInputStream(new FileInputStream(file));
			result = readAndClose(input);
		} catch (FileNotFoundException ex) {
			Printer.debugln(""+ex);
		}
		return result;
	}

	// Read
	private static byte[] readAndClose(InputStream aInput) {
		byte[] bucket = new byte[32 * 1024];
		ByteArrayOutputStream result = null;
		try {
			try {

				result = new ByteArrayOutputStream(bucket.length);
				int bytesRead = 0;
				while (bytesRead != -1) {
					bytesRead = aInput.read(bucket);
					if (bytesRead > 0) {
						result.write(bucket, 0, bytesRead);
					}
				}
			} finally {
				aInput.close();
			}
		} catch (IOException ex) {
			Printer.debugln(""+ex);
		}
		return result.toByteArray();
	}

	// ***********************************************************************************************//

	///////////////////// Transform an array of bytes to an integer based on a
	///////////////////// specific number of bits needed
	// Note that these functionalities can be further enhanced for better
	///////////////////// performances /////////////////////////////

	// ***********************************************************************************************//

	public static int getBit(byte[] data, int pos) {
		int posByte = pos / 8;
		int posBit = pos % 8;
		byte valByte = data[posByte];
		int valInt = valByte >> (8 - (posBit + 1)) & 0x0001;
		return valInt;
	}

	public static int[] getBits(byte[] data, int numberOfBits) {
		int[] bitArray = new int[numberOfBits];
		for (int j = 0; j < numberOfBits; j++) {
			bitArray[j] = getBit(data, j);
		}
		return bitArray;
	}

	public static int getIntFromByte(byte[] byteArray, int numberOfBits) {
		int result = 0;
		int[] bitArray = getBits(byteArray, numberOfBits);

		for (int i = 0; i < numberOfBits; i++) {
			result = result + (int) bitArray[i] * (int) Math.pow(2, i);
		}
		return result;
	}

	public static long getLongFromByte(byte[] byteArray, int numberOfBits) {
		long result = 0;
		int[] bitArray = getBits(byteArray, numberOfBits);

		for (int i = 0; i < numberOfBits; i++) {
			result = result + bitArray[i] * (int) Math.pow(2, i);
		}
		return result;
	}

	public static boolean[] intToBoolean(int number, int numberOfBits) {
		boolean[] pathNumber = new boolean[numberOfBits];

		// represent the number in a binary vector
		String s = Integer.toString(number, 2);
		String s1 = "";
		for (int i = 0; i < s.length(); i++) {
			s1 = s1 + s.charAt(s.length() - i - 1);
		}

		// pad the binary vector by zeros to have the same length as the number
		// of bits requested
		while (s1.length() < numberOfBits) {
			s1 = s1 + "0";
		}

		// convert the string s to an integer representation of bits (specially
		// in a boolean array)
		for (int i = 0; i < numberOfBits; i++) {
			pathNumber[i] = (s1.charAt(i) != '0');
		}
		return pathNumber;
	}

	public static String booleanToString(boolean[] message) {
		String result = "";
		for (int i = 0; i < message.length; i++) {

			if (message[i] == true) {
				result = result + 1;

			} else {
				result = result + 0;

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
	// ***********************************************************************************************//

	///////////////////// byte array concatenation /////////////////////////////

	// ***********************************************************************************************//

	public static byte[] concat(byte[] a, byte[] b) {
		int aLen = a.length;
		int bLen = b.length;
		byte[] c = new byte[aLen + bLen];
		System.arraycopy(a, 0, c, 0, aLen);
		System.arraycopy(b, 0, c, aLen, bLen);
		return c;
	}

}
