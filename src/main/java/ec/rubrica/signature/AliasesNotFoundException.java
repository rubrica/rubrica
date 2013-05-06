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
 * Excecion lanzada al no encontrar un alias en un KeyStore.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 * @deprecated
 */
public class AliasesNotFoundException extends Exception {

	public AliasesNotFoundException() {
	}

	public AliasesNotFoundException(String message) {
		super(message);
	}

	public AliasesNotFoundException(Throwable cause) {
		super(cause);
	}

	public AliasesNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}
}