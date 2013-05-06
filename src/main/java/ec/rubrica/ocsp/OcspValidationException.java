/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.ocsp;

import java.util.Date;

/**
 * Excepcion que se lanza en caso de haya un problema de validacion OCSP.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class OcspValidationException extends Exception {

	private static final long serialVersionUID = 3850292634299899214L;

	private int revocationReason;
	private Date revocationTime;

	public OcspValidationException(int revocationReason, Date revocationTime) {
		super();
		this.revocationReason = revocationReason;
		this.revocationTime = revocationTime;
	}

	public int getRevocationReason() {
		return revocationReason;
	}

	public Date getRevocationTime() {
		return revocationTime;
	}
}