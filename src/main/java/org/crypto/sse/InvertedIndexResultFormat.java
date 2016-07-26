//***********************************************************************************************//
// Information to manipulate Bloom Filters
//***********************************************************************************************//

package org.crypto.sse ;
import java.io.Serializable;

public class InvertedIndexResultFormat implements Serializable{

	
	public byte [] encryptedID;
	public byte [] bloomFilterId;
	
	public InvertedIndexResultFormat (byte [] encryptedID, byte [] bloomFilterId){
		this.encryptedID	=	encryptedID;
		this.bloomFilterId	=	bloomFilterId;	
	}

	public byte[] getEncryptedID() {
		return encryptedID;
	}

	public void setEncryptedID(byte[] encryptedID) {
		this.encryptedID = encryptedID;
	}

	public byte[] getBloomFilterId() {
		return bloomFilterId;
	}

	public void setBloomFilterId(byte[] bloomFilterId) {
		this.bloomFilterId = bloomFilterId;
	}
	
	
}
