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

package io.rubrica.certificate.ec.bce;

import static io.rubrica.certificate.ec.bce.CertificadoBancoCentral.OID_CEDULA_PASAPORTE;
import static io.rubrica.certificate.ec.bce.CertificadoBancoCentral.OID_CERTIFICADO_FUNCIONARIO_PUBLICO;
import static io.rubrica.certificate.ec.bce.CertificadoBancoCentral.OID_CERTIFICADO_PERSONA_JURIDICA;
import static io.rubrica.certificate.ec.bce.CertificadoBancoCentral.OID_CERTIFICADO_PERSONA_NATURAL;
import static io.rubrica.util.BouncyCastleUtils.certificateHasPolicy;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo CertificadoBancoCentral a partir de
 * certificados X509Certificate.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class CertificadoBancoCentralFactory {

	public static boolean esCertificadoDelBancoCentral(X509Certificate certificado) {
		byte[] valor = certificado.getExtensionValue(OID_CEDULA_PASAPORTE);
		return (valor != null);
	}

	public static boolean estTestCa(X509Certificate certificado) {
		return certificado.getIssuerDN().getName().contains("TEST");
	}

	public static CertificadoBancoCentral construir(X509Certificate certificado) {
		if (!esCertificadoDelBancoCentral(certificado)) {
			throw new IllegalStateException("Este no es un certificado emitido por el Banco Central del Ecuador");
		}

		if (certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_NATURAL)) {
			return new CertificadoPersonaNaturalBancoCentral(certificado);
		} else if (certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_JURIDICA)) {
			return new CertificadoPersonaJuridicaBancoCentral(certificado);
		} else if (certificateHasPolicy(certificado, OID_CERTIFICADO_FUNCIONARIO_PUBLICO)) {
			return new CertificadoFuncionarioPublicoBancoCentral(certificado);
		} else {
			throw new RuntimeException("Certificado del Banco Central del Ecuador de tipo desconocido!");
		}
	}
}