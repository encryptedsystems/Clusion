//***********************************************************************************************//
// SecureSetMFormat Object description
//***********************************************************************************************//

package org.crypto.sse ;

import java.io.Serializable;

public class SecureSetMFormat implements Serializable{

	public boolean[] secureSetM;
	public String identifier;

	public SecureSetMFormat(boolean[] secureSetM, String identifier){
		this.identifier=	identifier;
		this.secureSetM=	secureSetM;
	}

	public boolean[] getSecureSetM() {
		return secureSetM;
	}

	public void setSecureSetM(boolean[] secureSetM) {
		this.secureSetM = secureSetM;
	}

	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}



}
