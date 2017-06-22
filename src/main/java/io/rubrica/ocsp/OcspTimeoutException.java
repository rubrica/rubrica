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

import java.net.URL;

/**
 * Excepcion que se lanza en caso de que el servidor OCSP de timeout.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class OcspTimeoutException extends Exception {

	private static final long serialVersionUID = 8593563176075864415L;

	private String url;

	public OcspTimeoutException(Exception e, URL url) {
		super(e);
		this.url = url.toString();
	}

	public String getUrl() {
		return this.url;
	}
}