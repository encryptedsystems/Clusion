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

public class Token implements Serializable {

	public byte[][] tokenMMGlobal;
	public byte[] tokenSI1;
	public byte[] tokenSI2;
	public List<List<byte[]>> tokenSM = new ArrayList<List<byte[]>>();

	public Token(List<String> subSearch, List<byte[]> listOfkeys, int maxLengthOfMask, int falsePosRate)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			IOException {

		this.tokenMMGlobal = RR2Lev.token(listOfkeys.get(1), subSearch.get(0));

		this.tokenSI1 = TSet.token(listOfkeys.get(1), subSearch.get(0));

		for (int i = 1; i < subSearch.size(); i++) {
			tokenSM.add(ZMF.genTokSMV2(listOfkeys.get(0), subSearch.get(0), subSearch.get(i), maxLengthOfMask,
					falsePosRate));
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
