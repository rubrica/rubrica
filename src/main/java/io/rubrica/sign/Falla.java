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

package io.rubrica.sign;

import java.security.cert.Certificate;

/**
 * Falla en la verificacion de una Firma.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class Falla {

	private Certificate certificado;
	private String mensaje;

	public Falla(String mensaje) {
		this.setCertificado(null);
		this.setMensaje(mensaje);
	}

	public Falla(Certificate certificado, String mensaje) {
		this.setCertificado(certificado);
		this.setMensaje(mensaje);
	}

	/**
	 * @return the certificado
	 */
	public Certificate getCertificado() {
		return certificado;
	}

	/**
	 * @param certificado
	 *            the certificado to set
	 */
	public void setCertificado(Certificate certificado) {
		this.certificado = certificado;
	}

	/**
	 * @return the mensaje
	 */
	public String getMensaje() {
		return mensaje;
	}

	/**
	 * @param mensaje
	 *            the mensaje to set
	 */
	public void setMensaje(String mensaje) {
		this.mensaje = mensaje;
	}
}