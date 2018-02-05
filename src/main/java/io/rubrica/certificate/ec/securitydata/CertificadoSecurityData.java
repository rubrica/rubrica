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

package io.rubrica.certificate.ec.securitydata;

import java.io.IOException;
import java.security.cert.X509Certificate;

import io.rubrica.certificate.CertUtils;

/**
 * Certificado emitido por Security Data.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public abstract class CertificadoSecurityData {

	// OIDs de Tipo de Certificado
	public static final String OID_TIPO_PERSONA_NATURAL = "1.3.6.1.4.1.37746.2.7";
	public static final String OID_TIPO_PERSONA_JURIDICA_EMPRESA = "1.3.6.1.4.1.37746.2.8";
	public static final String OID_TIPO_REPRESENTANTE_LEGAL = "1.3.6.1.4.1.37746.2.9";
	public static final String OID_TIPO_MIEMBRO_EMPRESA = "1.3.6.1.4.1.37746.2.10";
	public static final String OID_TIPO_FUNCIONARIO_PUBLICO = "1.3.6.1.4.1.37746.2.11";
	public static final String OID_TIPO_PRUEBA = "1.3.6.1.4.1.37746.2.13";
	public static final String OID_TIPO_PERSONA_NATURAL_PROFESIONAL = "1.3.6.1.4.1.37746.2.15"; // uh?

	// OIDs de Campos del Certificado:
	public static final String OID_CEDULA_PASAPORTE = "1.3.6.1.4.1.37746.3.1";
	public static final String OID_NOMBRES = "1.3.6.1.4.1.37746.3.2";
	public static final String OID_PRIMER_APELLIDO = "1.3.6.1.4.1.37746.3.3";
	public static final String OID_SEGUNDO_APELLIDO = "1.3.6.1.4.1.37746.3.4";
	public static final String OID_CARGO = "1.3.6.1.4.1.37746.3.5";
	public static final String OID_INSTITUCION = "1.3.6.1.4.1.37746.3.6";
	public static final String OID_DIRECCION = "1.3.6.1.4.1.37746.3.7";
	public static final String OID_TELEFONO = "1.3.6.1.4.1.37746.3.8";
	public static final String OID_CIUDAD = "1.3.6.1.4.1.37746.3.9";
	public static final String OID_RAZON_SOCIAL = "1.3.6.1.4.1.37746.3.10";
	public static final String OID_RUC = "1.3.6.1.4.1.37746.3.11";
	public static final String OID_PAIS = "1.3.6.1.4.1.37746.3.12";
	public static final String OID_NOMBRE_REPRESENTANTE_LEGAL = "1.3.6.1.4.1.37746.3.26";
	public static final String OID_RUP = "1.3.6.1.4.1.37746.3.29";
	public static final String OID_PROFESION = "1.3.6.1.4.1.37746.3.30";
	public static final String OID_NUMERO_FACTURA = "1.3.6.1.4.1.37746.3.32";
	public static final String OID_NUMERO_SERIE_TOKEN = "1.3.6.1.4.1.37746.3.33";

	/** Certificado a analizar */
	private X509Certificate certificado;

	/**
	 * Permite analizar los contenidos de un X509Certificate segun las OIDs de
	 * Security Data.
	 * 
	 * @param certificado
	 */
	public CertificadoSecurityData(X509Certificate certificado) {
		this.certificado = certificado;
	}

	/**
	 * Obtiene el Número de Factura de la adquisicion de este certificado.
	 * 
	 * @return
	 */
	public String getNumeroFactura() {
		return obtenerExtension(OID_NUMERO_FACTURA);
	}

	/**
	 * Obtiene el Número de Serie del Token
	 * 
	 * @return
	 */
	public String getNumeroSerieToken() {
		return obtenerExtension(OID_NUMERO_SERIE_TOKEN);
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

	public String getNombres() {
		return obtenerExtension(OID_NOMBRES);
	}

	public String getPrimerApellido() {
		return obtenerExtension(OID_PRIMER_APELLIDO);
	}

	public String getSegundoApellido() {
		return obtenerExtension(OID_SEGUNDO_APELLIDO);
	}
}