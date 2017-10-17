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

import java.io.IOException;
import java.security.cert.X509Certificate;

import io.rubrica.certificate.CertUtils;

/**
 * Certificado emitido por Security Data.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public abstract class CertificadoSecurityDataOld {

	// OIDs de Tipo de Certificado
	public static final String OID_TIPO_PERSONA_NATURAL = "1.3.6.1.4.1.37746.207";
	public static final String OID_TIPO_PERSONA_JURIDICA_EMPRESA = "1.3.6.1.4.1.37746.208";
	public static final String OID_TIPO_REPRESENTANTE_LEGAL = "1.3.6.1.4.1.37746.209";
	public static final String OID_TIPO_MIEMBRO_EMPRESA = "1.3.6.1.4.1.37746.210";
	public static final String OID_TIPO_FUNCIONARIO_PUBLICO = "1.3.6.1.4.1.37746.211";

	// OIDs de Campos del Certificado:
	public static final String OID_NOMBRES = "1.3.6.1.4.1.37746.214";
	public static final String OID_PRIMER_APELLIDO = "1.3.6.1.4.1.37746.215";
	public static final String OID_SEGUNDO_APELLIDO = "1.3.6.1.4.1.37746.216";
	public static final String OID_RUP = "1.3.6.1.4.1.37746.217";
	public static final String OID_DIRECCION = "1.3.6.1.4.1.37746.218";
	public static final String OID_CIUDAD = "1.3.6.1.4.1.37746.219";
	public static final String OID_TELEFONO = "1.3.6.1.4.1.37746.220";
	public static final String OID_RAZON_SOCIAL = "1.3.6.1.4.1.37746.221";
	public static final String OID_RUC = "1.3.6.1.4.1.37746.222";
	public static final String OID_NOMBRE_REPRESENTANTE_LEGAL = "1.3.6.1.4.1.37746.223";
	public static final String OID_CEDULA_PASAPORTE = "1.3.6.1.4.1.37746.224";
	public static final String OID_CARGO = "1.3.6.1.4.1.37746.225";
	public static final String OID_INSTITUCION = "1.3.6.1.4.1.37746.226";
	public static final String OID_PAIS = "1.3.6.1.4.1.37746.229";

	/** Certificado a analizar */
	private X509Certificate certificado;

	/**
	 * Permite analizar los contenidos de un X509Certificate segun las OIDs de
	 * Security Data.
	 * 
	 * @param certificado
	 */
	public CertificadoSecurityDataOld(X509Certificate certificado) {
		this.certificado = certificado;
	}

	/**
	 * Retorna el valor de la extension, y una cadena vacia si no existe.
	 * 
	 * @param oid
	 * @return
	 */
	protected String obtenerExtension(String oid) {
		try {
			String valor = CertUtils.getExtensionValue(certificado, oid);
			return (valor != null) ? valor : "";
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}