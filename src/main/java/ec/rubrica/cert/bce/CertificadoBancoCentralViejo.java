/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.cert.bce;

import java.security.cert.X509Certificate;

/**
 * Certificado emitido por el Banco Central del Ecuador, version anterior.
 * 
 * @deprecated
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class CertificadoBancoCentralViejo {

	// OIDs de Campos del Certificado:
	private static final String OID_CEDULA = "1.2.3.4.1";
	private static final String OID_NOMBRES = "1.2.3.4.2";
	private static final String OID_APELLIDO_PATERNO = "1.2.3.4.3";
	private static final String OID_APELLIDO_MATERNO = "1.2.3.4.4";
	private static final String OID_CARGO = "1.2.3.4.5";
	private static final String OID_ORGANIZACION = "1.2.3.4.6";

	private X509Certificate certificado;

	public CertificadoBancoCentralViejo(X509Certificate certificado) {
		this.certificado = certificado;
	}

	public String getCedula() {
		return obtenerExtension(OID_CEDULA);
	}

	public String getOrganizazion() {
		return obtenerExtension(OID_ORGANIZACION);
	}

	public String getRepresentante() {
		String representante = obtenerExtension(OID_NOMBRES) + " "
				+ obtenerExtension(OID_APELLIDO_PATERNO);

		if (!obtenerExtension(OID_APELLIDO_MATERNO).isEmpty()) {
			representante = representante + " "
					+ obtenerExtension(OID_APELLIDO_MATERNO);
		}

		return representante;
	}

	public String getCargo() {
		return obtenerExtension(OID_CARGO);
	}

	/**
	 * Retorna el valor de la extension, y una cadena vacia si no existe.
	 * 
	 * @param oid
	 * @return
	 */
	protected String obtenerExtension(String oid) {
		byte[] valor = certificado.getExtensionValue(oid);
		return (valor != null) ? new String(valor) : "";
	}
}