/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.pdf;

import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;

import sun.security.provider.certpath.OCSP;
import sun.security.provider.certpath.OCSP.RevocationStatus;
import sun.security.provider.certpath.OCSP.RevocationStatus.CertStatus;
import ec.rubrica.cert.bce.BceSubCert;
import ec.rubrica.cert.bce.BceSubTestCert;
import ec.rubrica.cert.bce.CertificadoBancoCentralFactory;
import ec.rubrica.cert.securitydata.CertificadoSecurityDataFactory;
import ec.rubrica.cert.securitydata.SecurityDataSubCaCert;
import ec.rubrica.cert.securitydata.old.CertificadoSecurityDataOldFactory;

/**
 * Verifica un certificado contra un servidor OCSP.
 * 
 * Es solamente un ejemplo, ya que utiliza la clase
 * <code>sun.security.provider.certpath.OCSP</code>, asi que no debe utilizarse
 * de manera directa.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
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