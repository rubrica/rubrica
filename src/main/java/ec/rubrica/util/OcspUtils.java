/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.util;

import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.Reason;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ec.rubrica.cert.bce.BceCaCert;
import ec.rubrica.cert.bce.BceCaTestCert;
import ec.rubrica.cert.bce.BceSubCert;
import ec.rubrica.cert.bce.BceSubTestCert;
import ec.rubrica.cert.bce.CertificadoBancoCentralFactory;
import ec.rubrica.cert.securitydata.CertificadoSecurityDataFactory;
import ec.rubrica.cert.securitydata.SecurityDataCaCert;
import ec.rubrica.cert.securitydata.SecurityDataSubCaCert;
import ec.rubrica.cert.securitydata.old.CertificadoSecurityDataOldFactory;

public class OcspUtils {

	public static boolean isValidCertificate(X509Certificate certificate) {

		List<X509Certificate> certs = new ArrayList<X509Certificate>();
		certs.add(certificate);

		if (CertificadoSecurityDataFactory
				.esCertificadoDeSecurityData(certificate)
				|| CertificadoSecurityDataOldFactory
						.esCertificadoDeSecurityDataOld(certificate)) {
			certs.add(new SecurityDataSubCaCert());
		} else if (CertificadoBancoCentralFactory
				.esCertificadoDelBancoCentral(certificate)) {
			if (CertificadoBancoCentralFactory.estTestCa(certificate)) {
				certs.add(new BceSubTestCert());
			} else {
				certs.add(new BceSubCert());
			}
		}

		// init certification path
		CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X509");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
		CertPath cp;
		try {
			cp = cf.generateCertPath(certs);
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}

		// load the root CA certificates
		X509Certificate rootCACert1 = new SecurityDataCaCert();
		X509Certificate rootCACert2 = new BceCaCert();
		X509Certificate rootCACert3 = new BceCaTestCert();

		// init root trusted certs
		TrustAnchor ta1 = new TrustAnchor(rootCACert1, null);
		TrustAnchor ta2 = new TrustAnchor(rootCACert2, null);
		TrustAnchor ta3 = new TrustAnchor(rootCACert3, null);

		Set<TrustAnchor> trustedCertsSet = new HashSet<TrustAnchor>();
		trustedCertsSet.add(ta1);
		trustedCertsSet.add(ta2);
		trustedCertsSet.add(ta3);

		// init PKIX parameters
		PKIXParameters params;
		try {
			params = new PKIXParameters(trustedCertsSet);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}

		// if (CertificadoSecurityDataFactory
		// .esCertificadoDeSecurityData(certificate)
		// || CertificadoSecurityDataOldFactory
		// .esCertificadoDeSecurityDataOld(certificate)) {
		//
		// }

		params.setRevocationEnabled(true);

		// enable OCSP
		Security.setProperty("ocsp.enable", "true");

		// Activate CRLDP
		System.setProperty("com.sun.security.enableCRLDP", "true");

		// perform validation
		CertPathValidator validator;
		try {
			validator = CertPathValidator.getInstance("PKIX");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

		try {
			CertPathValidatorResult result = validator.validate(cp, params);
			return true;
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		} catch (CertPathValidatorException e) {
			Reason reason = e.getReason();
			int index = e.getIndex();
			System.out.println("reason=" + reason + "; index=" + index);

			e.printStackTrace();
			Throwable t = e.getCause();

			if (t != null) {
				System.out.println("Cause=" + t.getClass());
				t.printStackTrace();

				if (t instanceof SocketTimeoutException) {
					System.out.println("Timeout al ir al OCSP server!");
					// FIXME
					return false;
				}
			}

			return false;
		}

		// X509Certificate trustedCert = (X509Certificate) cpv_result
		// .getTrustAnchor().getTrustedCert();
	}
}