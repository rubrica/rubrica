/*
 * Copyright 2009-2018 Rubrica
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

package io.rubrica.certificate.ec.cj;

import java.io.IOException;
import java.security.cert.X509Certificate;

import io.rubrica.certificate.CertUtils;

/**
 * Certificado emitido por el Banco Central del Ecuador.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public abstract class CertificadoConsejoJudicatura {

	// OIDs de tipo de certificado:
	public static final String OID_CERTIFICADO_PERSONA_NATURAL = "1.3.6.1.4.1.43745.1.2.1.1";
	public static final String OID_CERTIFICADO_PERSONA_JURIDICA_PRIVADA = "1.3.6.1.4.1.43745.1.2.1.2";
	public static final String OID_CERTIFICADO_PERSONA_JURIDICA_PUBLICA = "1.3.6.1.4.1.43745.1.2.1.3";
	public static final String OID_CERTIFICADO_MIEMBRO_EMPRESA = "1.3.6.1.4.1.43745.1.2.1.4";
	public static final String OID_CERTIFICADO_EMPRESA = "1.3.6.1.4.1.43745.1.2.2.1";
	public static final String OID_CERTIFICADO_DEPARTAMENTO_EMPRESA = "1.3.6.1.4.1.43745.1.2.3.1";

	// OIDs de Campos del Certificado:
	public static final String OID_CEDULA_PASAPORTE = "1.3.6.1.4.1.43745.1.3.1";
	public static final String OID_NOMBRES = "1.3.6.1.4.1.43745.1.3.2";
	public static final String OID_APELLIDO_1 = "1.3.6.1.4.1.43745.1.3.3";
	public static final String OID_APELLIDO_2 = "1.3.6.1.4.1.43745.1.3.4";
	public static final String OID_CARGO = "1.3.6.1.4.1.43745.1.3.5";
	public static final String OID_INSTITUCION = "1.3.6.1.4.1.43745.1.3.6";
	public static final String OID_DIRECCION = "1.3.6.1.4.1.43745.1.3.7";
	public static final String OID_TELEFONO = "1.3.6.1.4.1.43745.1.3.8";
	public static final String OID_CIUDAD = "1.3.6.1.4.1.43745.1.3.9";
	public static final String OID_RAZON_SOCIAL = "1.3.6.1.4.1.43745.1.3.10";
	public static final String OID_RUC = "1.3.6.1.4.1.43745.1.3.11";
	public static final String OID_PAIS = "1.3.6.1.4.1.43745.1.3.12";
	public static final String OID_CERTIFICADO = "1.3.6.1.4.1.43745.1.3.50";
	public static final String OID_CONTENEDOR = "1.3.6.1.4.1.43745.1.3.51";
	public static final String OID_RUP = "1.3.6.1.4.1.43745.1.3.52";
	public static final String OID_PROFESION = "1.3.6.1.4.1.43745.1.3.53";
	public static final String OID_DEPARTAMENTO = "1.3.6.1.4.1.43745.1.3.54";

	/** Certificado a analizar */
	private X509Certificate certificado;

	public CertificadoConsejoJudicatura(X509Certificate certificado) {
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
			String valor = CertUtils.getExtensionValueSubjectAlternativeNames(certificado, oid);
			return (valor != null) ? valor : "";
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}