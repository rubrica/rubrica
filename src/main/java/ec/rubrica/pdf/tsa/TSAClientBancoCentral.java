/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.pdf.tsa;

import com.itextpdf.text.pdf.security.TSAClient;

/**
 * Implementacion de cliente TSA para utilizar el servidor de Time Stamping del
 * Banco Central del Ecuador.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class TSAClientBancoCentral extends TSAClientBouncyCastleWithOid
		implements TSAClient {

	// OID del Banco Central
	private static final String OID = "1.3.6.1.4.1.37947.4.10";

	public TSAClientBancoCentral(String url) {
		super(url, OID);
	}
}