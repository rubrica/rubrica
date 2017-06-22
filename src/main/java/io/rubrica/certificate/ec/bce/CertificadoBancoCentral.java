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

package io.rubrica.certificate.ec.bce;

import java.io.IOException;
import java.security.cert.X509Certificate;

import io.rubrica.certificate.CertUtils;

/**
 * Certificado emitido por el Banco Central del Ecuador.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public abstract class CertificadoBancoCentral {

	// OIDs de tipo de certificado:
	public static final String OID_CERTIFICADO_PERSONA_NATURAL = "1.3.6.1.4.1.37947.2.1.1";
	public static final String OID_CERTIFICADO_PERSONA_JURIDICA = "1.3.6.1.4.1.37947.2.2.1";
	public static final String OID_CERTIFICADO_FUNCIONARIO_PUBLICO = "1.3.6.1.4.1.37947.2.3.1";

	// OIDs de Campos del Certificado:
	public static final String OID_CEDULA_PASAPORTE = "1.3.6.1.4.1.37947.3.1";
	public static final String OID_NOMBRES = "1.3.6.1.4.1.37947.3.2";
	public static final String OID_APELLIDO_1 = "1.3.6.1.4.1.37947.3.3";
	public static final String OID_APELLIDO_2 = "1.3.6.1.4.1.37947.3.4";
	public static final String OID_CARGO = "1.3.6.1.4.1.37947.3.5";
	public static final String OID_INSTITUCION = "1.3.6.1.4.1.37947.3.6";
	public static final String OID_DIRECCION = "1.3.6.1.4.1.37947.3.7";
	public static final String OID_TELEFONO = "1.3.6.1.4.1.37947.3.8";
	public static final String OID_CIUDAD = "1.3.6.1.4.1.37947.3.9";
	public static final String OID_RAZON_SOCIAL = "1.3.6.1.4.1.37947.3.10";
	public static final String OID_RUC = "1.3.6.1.4.1.37947.3.11";

	// BUG: En la documentacion del BCE no esta incluido?
	public static final String OID_PAIS = "1.3.6.1.4.1.37947.3.12";

	public static final String OID_CONTENEDOR = "1.3.6.1.4.1.37947.3.100";

	/** Certificado a analizar */
	private X509Certificate certificado;

	public CertificadoBancoCentral(X509Certificate certificado) {
		this.certificado = certificado;
	}

	public String getContenedor() {
		return obtenerExtension(OID_CONTENEDOR);
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