//***********************************************************************************************//

/////////////////////    Generation of the token of IEX-ZMF (adapted for both Cash et al. (Crypto'13) and (NDSS'14)
//***********************************************************************************************//	

package org.crypto.sse;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;

public class Token implements Serializable{

	public byte[][] tokenMMGlobal;
	public byte[] tokenSI1;
	public byte[] tokenSI2;
	public List<List<byte[]>> tokenSM	=	new ArrayList<List<byte[]>>();



	public Token(List<String> subSearch, List<byte[]> listOfkeys, int maxLengthOfMask, int falsePosRate) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException{

		this.tokenMMGlobal	=	MMGlobal.genToken(listOfkeys.get(1), subSearch.get(0));

		this.tokenSI1	=	InvertedIndex.genTokSI(listOfkeys.get(1), subSearch.get(0));

		for (int i=1; i<subSearch.size(); i++){
			tokenSM.add(ZMF.genTokSMV2(listOfkeys.get(0), subSearch.get(0), subSearch.get(i), maxLengthOfMask, falsePosRate));
		}

	}


	public byte[] getTokenSI1() {
		return tokenSI1;
	}

	public byte[][] getTokenMMGlobal() {
		return tokenMMGlobal;
	}


	public void setTokenSI1(byte[] tokenSI1) {
		this.tokenSI1 = tokenSI1;
	}



	public byte[] getTokenSI2() {
		return tokenSI2;
	}


	public void setTokenSI2(byte[] tokenSI2) {
		this.tokenSI2 = tokenSI2;
	}



	public List<List<byte[]>> getTokenSM() {
		return tokenSM;
	}



	public void setTokenSM(List<List<byte[]>> tokenSM) {
		this.tokenSM = tokenSM;
	}

}

