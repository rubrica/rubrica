/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.keystore;

/**
 * Excepcion que se lanza si un driver de token no esta instalado.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class DriverNoInstaladoException extends Exception {

	private static final long serialVersionUID = -1404206068069771747L;

	public DriverNoInstaladoException() {
		super();
	}
}