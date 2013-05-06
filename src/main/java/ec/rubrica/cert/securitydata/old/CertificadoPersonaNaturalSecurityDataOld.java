/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.cert.securitydata.old;

import java.security.cert.X509Certificate;

import ec.rubrica.cert.CertificadoPersonaNatural;

/**
 * Certificado de Persona Natural emitido por Security Data.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class CertificadoPersonaNaturalSecurityDataOld extends
		CertificadoSecurityDataOld implements CertificadoPersonaNatural {

	public CertificadoPersonaNaturalSecurityDataOld(X509Certificate certificado) {
		super(certificado);
	}

	public String getCedulaPasaporte() {
		return obtenerExtension(OID_CEDULA_PASAPORTE);
	}

	public String getNombres() {
		return obtenerExtension(OID_NOMBRES);
	}

	public String getPrimerApellido() {
		return obtenerExtension(OID_PRIMER_APELLIDO);
	}

	public String getSegundoApellido() {
		return obtenerExtension(OID_SEGUNDO_APELLIDO);
	}

	public String getDireccion() {
		return obtenerExtension(OID_DIRECCION);
	}

	public String getTelefono() {
		return obtenerExtension(OID_TELEFONO);
	}

	public String getCiudad() {
		return obtenerExtension(OID_CIUDAD);
	}

	public String getPais() {
		return obtenerExtension(OID_PAIS);
	}

	public String getRuc() {
		return obtenerExtension(OID_RUC);
	}

	public String getRup() {
		return obtenerExtension(OID_RUP);
	}
}