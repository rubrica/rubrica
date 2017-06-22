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

package io.rubrica.core;

/**
 * Excepcion lanzada si ocurre un error al verificar una firma.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
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