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
// Record Object description used to better handle the Matryoshka filters along with the encrypted
// documents identifiers.
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
