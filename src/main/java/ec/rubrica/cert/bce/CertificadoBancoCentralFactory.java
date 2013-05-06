/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.cert.bce;

import static ec.rubrica.cert.bce.CertificadoBancoCentral.OID_CEDULA_PASAPORTE;
import static ec.rubrica.cert.bce.CertificadoBancoCentral.OID_CERTIFICADO_FUNCIONARIO_PUBLICO;
import static ec.rubrica.cert.bce.CertificadoBancoCentral.OID_CERTIFICADO_PERSONA_JURIDICA;
import static ec.rubrica.cert.bce.CertificadoBancoCentral.OID_CERTIFICADO_PERSONA_NATURAL;
import static ec.rubrica.util.BouncyCastleUtils.certificateHasPolicy;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo CertificadoBancoCentral a partir de
 * certificados X509Certificate.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class CertificadoBancoCentralFactory {

	public static boolean esCertificadoDelBancoCentral(
			X509Certificate certificado) {
		byte[] valor = certificado.getExtensionValue(OID_CEDULA_PASAPORTE);
		return (valor != null);
	}

	public static boolean estTestCa(X509Certificate certificado) {
		return certificado.getIssuerDN().getName().contains("TEST");
	}

	public static CertificadoBancoCentral construir(X509Certificate certificado) {
		if (!esCertificadoDelBancoCentral(certificado)) {
			throw new IllegalStateException(
					"Este no es un certificado emitido por el Banco Central del Ecuador");
		}

		if (certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_NATURAL)) {
			return new CertificadoPersonaNaturalBancoCentral(certificado);
		} else if (certificateHasPolicy(certificado,
				OID_CERTIFICADO_PERSONA_JURIDICA)) {
			return new CertificadoPersonaJuridicaBancoCentral(certificado);
		} else if (certificateHasPolicy(certificado,
				OID_CERTIFICADO_FUNCIONARIO_PUBLICO)) {
			return new CertificadoFuncionarioPublicoBancoCentral(certificado);
		} else {
			throw new RuntimeException(
					"Certificado del Banco Central del Ecuador de tipo desconocido!");
		}
	}
}