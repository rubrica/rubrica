/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.pdf;

import java.security.cert.Certificate;

/**
 * Falla en la verificacion de una Firma.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
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