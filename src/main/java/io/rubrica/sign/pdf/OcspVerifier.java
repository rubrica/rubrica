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

package io.rubrica.sign.pdf;

import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

import io.rubrica.certificate.ec.bce.BceSubCert;
import io.rubrica.certificate.ec.bce.BceSubTestCert;
import io.rubrica.certificate.ec.bce.CertificadoBancoCentralFactory;
import io.rubrica.certificate.ec.securitydata.CertificadoSecurityDataFactory;
import io.rubrica.certificate.ec.securitydata.SecurityDataSubCaCert;
import io.rubrica.certificate.ec.securitydata.old.CertificadoSecurityDataOldFactory;
import sun.security.provider.certpath.OCSP;
import sun.security.provider.certpath.OCSP.RevocationStatus;
import sun.security.provider.certpath.OCSP.RevocationStatus.CertStatus;

/**
 * Verifica un certificado contra un servidor OCSP.
 * 
 * Es solamente un ejemplo, ya que utiliza la clase
 * <code>sun.security.provider.certpath.OCSP</code>, asi que no debe utilizarse
 * de manera directa.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 * @deprecated
 */
public class OcspVerifier {

	public static boolean isRevocated(X509Certificate certificado)
			throws IOException {

		X509Certificate subCert = null;

		if (CertificadoSecurityDataFactory
				.esCertificadoDeSecurityData(certificado)
				|| CertificadoSecurityDataOldFactory
						.esCertificadoDeSecurityDataOld(certificado)) {
			subCert = new SecurityDataSubCaCert();
		} else if (CertificadoBancoCentralFactory
				.esCertificadoDelBancoCentral(certificado)) {
			if (CertificadoBancoCentralFactory.estTestCa(certificado)) {
				subCert = new BceSubTestCert();
			} else {
				subCert = new BceSubCert();
			}
		}

		try {
			RevocationStatus revStatus = OCSP.check(certificado, subCert);
			CertStatus v = revStatus.getCertStatus();
			return v.equals(CertStatus.REVOKED);
		} catch (CertPathValidatorException e) {
			throw new RuntimeException(e);
		}
	}
}