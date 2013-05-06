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

import ec.rubrica.cert.CertificadoFuncionarioPublico;

/**
 * Certificado de Funcionario Publico emitido por el Banco Central del Ecuador.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class CertificadoFuncionarioPublicoBancoCentral extends
		CertificadoBancoCentral implements CertificadoFuncionarioPublico {

	public CertificadoFuncionarioPublicoBancoCentral(X509Certificate certificado) {
		super(certificado);
	}

	public String getCedulaPasaporte() {
		return obtenerExtension(OID_CEDULA_PASAPORTE);
	}

	public String getNombres() {
		return obtenerExtension(OID_NOMBRES);
	}

	public String getPrimerApellido() {
		return obtenerExtension(OID_APELLIDO_1);
	}

	public String getSegundoApellido() {
		return obtenerExtension(OID_APELLIDO_2);
	}

	public String getCargo() {
		return obtenerExtension(OID_CARGO);
	}

	public String getInstitucion() {
		return obtenerExtension(OID_INSTITUCION);
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

	public String getRazonSocial() {
		return obtenerExtension(OID_RAZON_SOCIAL);
	}
}