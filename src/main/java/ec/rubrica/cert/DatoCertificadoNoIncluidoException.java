/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.cert;

/**
 * Excepcion que se lanza en caso de que el certificado no incluya un campo.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class DatoCertificadoNoIncluidoException extends RuntimeException {

	private static final long serialVersionUID = 5614921752347842642L;

	public DatoCertificadoNoIncluidoException(String message) {
		super(message);
	}
}