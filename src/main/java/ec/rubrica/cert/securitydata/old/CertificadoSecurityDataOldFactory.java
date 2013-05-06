/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.cert.securitydata.old;

import static ec.rubrica.cert.securitydata.old.CertificadoSecurityDataOld.OID_CEDULA_PASAPORTE;
import static ec.rubrica.cert.securitydata.old.CertificadoSecurityDataOld.OID_TIPO_FUNCIONARIO_PUBLICO;
import static ec.rubrica.cert.securitydata.old.CertificadoSecurityDataOld.OID_TIPO_MIEMBRO_EMPRESA;
import static ec.rubrica.cert.securitydata.old.CertificadoSecurityDataOld.OID_TIPO_PERSONA_JURIDICA_EMPRESA;
import static ec.rubrica.cert.securitydata.old.CertificadoSecurityDataOld.OID_TIPO_PERSONA_NATURAL;
import static ec.rubrica.cert.securitydata.old.CertificadoSecurityDataOld.OID_TIPO_REPRESENTANTE_LEGAL;
import static ec.rubrica.util.BouncyCastleUtils.certificateHasPolicy;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo CertificadoSecurityData a partir de
 * certificados X509Certificate.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class CertificadoSecurityDataOldFactory {

	public static boolean esCertificadoDeSecurityDataOld(
			X509Certificate certificado) {
		byte[] valor = certificado.getExtensionValue(OID_CEDULA_PASAPORTE);
		return (valor != null);
	}

	public static CertificadoSecurityDataOld construir(
			X509Certificate certificado) {
		if (certificateHasPolicy(certificado, OID_TIPO_PERSONA_NATURAL)) {
			return new CertificadoPersonaNaturalSecurityDataOld(certificado);
		} else if (certificateHasPolicy(certificado,
				OID_TIPO_PERSONA_JURIDICA_EMPRESA)) {
			return new CertificadoPersonaJuridicaSecurityDataOld(certificado);
		} else if (certificateHasPolicy(certificado,
				OID_TIPO_REPRESENTANTE_LEGAL)) {
			return new CertificadoRepresentanteLegalSecurityDataOld(certificado);
		} else if (certificateHasPolicy(certificado, OID_TIPO_MIEMBRO_EMPRESA)) {
			return new CertificadoMiembroEmpresaSecurityDataOld(certificado);
		} else if (certificateHasPolicy(certificado,
				OID_TIPO_FUNCIONARIO_PUBLICO)) {
			return new CertificadoFuncionarioPublicoSecurityDataOld(certificado);
		} else {
			throw new RuntimeException(
					"Tipo Certificado de SecurityData desconocido!");
		}
	}
}