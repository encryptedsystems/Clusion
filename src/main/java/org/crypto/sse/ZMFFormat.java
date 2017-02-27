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
// SecureSetMFormat Object description
//***********************************************************************************************//

package org.crypto.sse;

import java.io.Serializable;

public class ZMFFormat implements Serializable {

	public boolean[] secureSetM;
	public String identifier;

	public ZMFFormat(boolean[] secureSetM, String identifier) {
		this.identifier = identifier;
		this.secureSetM = secureSetM;
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
