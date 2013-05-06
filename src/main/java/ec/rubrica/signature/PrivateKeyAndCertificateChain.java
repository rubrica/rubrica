/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.signature;

import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * Objeto para almacenar un PrivateKey y un Certificate chain a la vez.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 * @deprecated
 */
public class PrivateKeyAndCertificateChain {

	private String alias;
	private PrivateKey privateKey;
	private Certificate[] certificateChain;

	public PrivateKeyAndCertificateChain(String alias, PrivateKey privateKey,
			Certificate[] certificateChain) {
		this.alias = alias;
		this.privateKey = privateKey;
		this.certificateChain = certificateChain;
	}

	public String getAlias() {
		return alias;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public Certificate[] getCertificateChain() {
		return certificateChain;
	}

	public String toString() {
		return alias;
	}
}