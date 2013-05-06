/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.cert.securitydata;

import java.security.cert.X509Certificate;

import ec.rubrica.cert.CertificadoPersonaJuridica;
import ec.rubrica.cert.DatoCertificadoNoIncluidoException;

/**
 * Certificado de Persona Juridica emitido por Security Data.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class CertificadoPersonaJuridicaSecurityData extends
		CertificadoSecurityData implements CertificadoPersonaJuridica {

	public CertificadoPersonaJuridicaSecurityData(X509Certificate certificado) {
		super(certificado);
	}

	public String getRazonSocial() {
		return obtenerExtension(OID_RAZON_SOCIAL);
	}

	public String getRuc() {
		return obtenerExtension(OID_RUC);
	}

	public String getCedulaPasaporte() {
		throw new DatoCertificadoNoIncluidoException(
				"Los certificados de Persona Juridica de Security Data no incluyen cedula o pasaporte");
	}

	public String getNombres() {
		throw new DatoCertificadoNoIncluidoException(
				"Los certificados de Persona Juridica de Security Data no incluyen nombre(s)");
	}

	public String getPrimerApellido() {
		throw new DatoCertificadoNoIncluidoException(
				"Los certificados de Persona Juridica de Security Data no incluyen primer apellido");
	}

	public String getSegundoApellido() {
		throw new DatoCertificadoNoIncluidoException(
				"Los certificados de Persona Juridica de Security Data no incluyen segundo apellido");
	}

	public String getCargo() {
		throw new DatoCertificadoNoIncluidoException(
				"Los certificados de Persona Juridica de Security Data no incluyen cargo");
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

	public String getRup() {
		return obtenerExtension(OID_RUP);
	}

	public String getNombreRepresentanteLegal() {
		return obtenerExtension(OID_NOMBRE_REPRESENTANTE_LEGAL);
	}
}