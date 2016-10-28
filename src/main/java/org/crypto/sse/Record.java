//***********************************************************************************************//
// Record Object description used to better handle the matryoshka filters
//***********************************************************************************************//

package org.crypto.sse;

import java.io.Serializable;

public class Record implements Serializable {

	byte[] label;
	byte[] value;

	public Record(byte[] label, byte[] value) {
		this.label = label;
		this.value = value;
	}

	public byte[] getLabel() {
		return label;
	}

	public void setLabel(byte[] label) {
		this.label = label;
	}

	public byte[] getValue() {
		return value;
	}

	public void setValue(byte[] value) {
		this.value = value;
	}

}
