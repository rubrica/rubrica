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

package io.rubrica.certificate.ec.securitydata.old;

import java.security.cert.X509Certificate;

import io.rubrica.certificate.DatoCertificadoNoIncluidoException;
import io.rubrica.certificate.ec.CertificadoPersonaJuridica;

/**
 * Certificado de Persona Juridica emitido por Security Data.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class CertificadoPersonaJuridicaSecurityDataOld extends
		CertificadoSecurityDataOld implements CertificadoPersonaJuridica {

	public CertificadoPersonaJuridicaSecurityDataOld(X509Certificate certificado) {
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