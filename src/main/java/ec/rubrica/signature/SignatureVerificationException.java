/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.signature;

/**
 * Excepcion lanzada si ocurre un error al verificar una firma.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class SignatureVerificationException extends Exception {

	private static final long serialVersionUID = 8692706681299088789L;

	public SignatureVerificationException() {
	}

	public SignatureVerificationException(String message) {
		super(message);
	}

	public SignatureVerificationException(Throwable cause) {
		super(cause);
	}

	public SignatureVerificationException(String message, Throwable cause) {
		super(message, cause);
	}
}