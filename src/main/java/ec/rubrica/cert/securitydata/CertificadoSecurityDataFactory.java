/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.cert.securitydata;

import static ec.rubrica.cert.securitydata.CertificadoSecurityData.OID_CEDULA_PASAPORTE;
import static ec.rubrica.cert.securitydata.CertificadoSecurityData.OID_TIPO_FUNCIONARIO_PUBLICO;
import static ec.rubrica.cert.securitydata.CertificadoSecurityData.OID_TIPO_MIEMBRO_EMPRESA;
import static ec.rubrica.cert.securitydata.CertificadoSecurityData.OID_TIPO_PERSONA_JURIDICA_EMPRESA;
import static ec.rubrica.cert.securitydata.CertificadoSecurityData.OID_TIPO_PERSONA_NATURAL;
import static ec.rubrica.cert.securitydata.CertificadoSecurityData.OID_TIPO_PERSONA_NATURAL_PROFESIONAL;
import static ec.rubrica.cert.securitydata.CertificadoSecurityData.OID_TIPO_PRUEBA;
import static ec.rubrica.cert.securitydata.CertificadoSecurityData.OID_TIPO_REPRESENTANTE_LEGAL;
import static ec.rubrica.util.BouncyCastleUtils.certificateHasPolicy;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo CertificadoSecurityData a partir de
 * certificados X509Certificate.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class CertificadoSecurityDataFactory {

	public static boolean esCertificadoDeSecurityData(
			X509Certificate certificado) {
		byte[] valor = certificado.getExtensionValue(OID_CEDULA_PASAPORTE);
		return (valor != null);
	}

	public static CertificadoSecurityData construir(X509Certificate certificado) {
		if (certificateHasPolicy(certificado, OID_TIPO_PERSONA_NATURAL)) {
			return new CertificadoPersonaNaturalSecurityData(certificado);
		} else if (certificateHasPolicy(certificado,
				OID_TIPO_PERSONA_JURIDICA_EMPRESA)) {
			return new CertificadoPersonaJuridicaSecurityData(certificado);
		} else if (certificateHasPolicy(certificado,
				OID_TIPO_REPRESENTANTE_LEGAL)) {
			return new CertificadoRepresentanteLegalSecurityData(certificado);
		} else if (certificateHasPolicy(certificado, OID_TIPO_MIEMBRO_EMPRESA)) {
			return new CertificadoMiembroEmpresaSecurityData(certificado);
		} else if (certificateHasPolicy(certificado,
				OID_TIPO_FUNCIONARIO_PUBLICO)) {
			return new CertificadoFuncionarioPublicoSecurityData(certificado);
		} else if (certificateHasPolicy(certificado,
				OID_TIPO_PERSONA_NATURAL_PROFESIONAL)) {
			return new CertificadoPersonaNaturalSecurityData(certificado);
		} else if (certificateHasPolicy(certificado, OID_TIPO_PRUEBA)) {
			return new CertificadoPruebaSecurityData(certificado);
		} else {
			throw new RuntimeException(
					"Tipo Certificado de SecurityData desconocido!");
		}
	}
}