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

/////////////////////    Generation of the token of IEX-ZMF 
//***********************************************************************************************//	

package org.crypto.sse;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

public class TokenDIS implements Serializable {

	public byte[][] tokenMMGlobal;
	public byte[] tokenDIC;
	public List<byte[][]> tokenMMLocal = new ArrayList<byte[][]>();

	public TokenDIS(List<String> subSearch, List<byte[]> listOfkeys) throws UnsupportedEncodingException {

		this.tokenMMGlobal = RR2Lev.token(listOfkeys.get(0), subSearch.get(0));
		this.tokenDIC = CryptoPrimitives.generateHmac(listOfkeys.get(1), 3 + subSearch.get(0));

		for (int i = 1; i < subSearch.size(); i++) {
			tokenMMLocal.add(
					RR2Lev.token(CryptoPrimitives.generateHmac(listOfkeys.get(0), subSearch.get(0)), subSearch.get(i)));
		}

	}

	public byte[][] getTokenMMGlobal() {
		return tokenMMGlobal;
	}

	public void setTokenMMGlobal(byte[][] tokenMMGlobal) {
		this.tokenMMGlobal = tokenMMGlobal;
	}

	public byte[] getTokenDIC() {
		return tokenDIC;
	}

	public void setTokenDIC(byte[] tokenDIC) {
		this.tokenDIC = tokenDIC;
	}

	public List<byte[][]> getTokenMMLocal() {
		return tokenMMLocal;
	}

	public void setTokenMMLocal(List<byte[][]> tokenMMLocal) {
		this.tokenMMLocal = tokenMMLocal;
	}

}
