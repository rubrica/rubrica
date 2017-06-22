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

package io.rubrica.ocsp;

import java.util.Date;

/**
 * Excepcion que se lanza en caso de haya un problema de validacion OCSP.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class OcspValidationException extends Exception {

	private static final long serialVersionUID = -4371520182817375302L;

	private int revocationReason;
	private Date revocationTime;

	public OcspValidationException() {
		super();
	}

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