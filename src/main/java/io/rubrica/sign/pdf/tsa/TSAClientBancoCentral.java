/*
 * Copyright 2009-2017 Rubrica
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package io.rubrica.sign.pdf.tsa;

import com.lowagie.text.pdf.TSAClient;

/**
 * Implementacion de cliente TSA para utilizar el servidor de Time Stamping del
 * Banco Central del Ecuador.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 * @deprecated
 */
public class TSAClientBancoCentral extends TSAClientBouncyCastleWithOid
		implements TSAClient {

	// OID del Banco Central
	private static final String OID = "1.3.6.1.4.1.37947.4.10";

	public TSAClientBancoCentral(String url) {
		//super(url, OID);
		super(url);
	}
}