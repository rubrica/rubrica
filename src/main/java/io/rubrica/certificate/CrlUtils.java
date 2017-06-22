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

package io.rubrica.certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.InitialDirContext;

import io.rubrica.core.RubricaException;
import io.rubrica.util.CertificateUtils;
import io.rubrica.util.HttpClient;
import io.rubrica.util.OcspUtils;

public class CrlUtils {

	private static final Logger logger = Logger.getLogger(CrlUtils.class.getName());

	public static ValidationResult verifyCertificateCRLs(X509Certificate cert, PublicKey vaPublicKey,
			List<String> overridingDistributionPoints) throws RubricaException {

		if (cert == null) {
			return ValidationResult.CORRUPT;
		}

		List<String> crlDistPoints;

		try {
			List<String> ocspUrls = CertificateUtils.getAuthorityInformationAccess(cert);
			for (String ocsp : ocspUrls) {
				System.out.println("OCSP=" + ocsp);
			}

			System.out.println("Valid? " + OcspUtils.isValidCertificate(cert));
			crlDistPoints = overridingDistributionPoints == null || overridingDistributionPoints.isEmpty()
					? CertificateUtils.getCrlDistributionPoints(cert) : overridingDistributionPoints;
		} catch (IOException e) {
			logger.severe("Error obteniendo los puntos de distribucion de CRL: " + e);
			return ValidationResult.SERVER_ERROR;
		}

		logger.fine("El certificado con serie '" + cert.getSerialNumber() + "' tiene asociadas las siguientes CRL: "
				+ crlDistPoints);

		CertificateFactory cf;

		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			logger.severe("Error instanciando la factoria de certificados: " + e);
			return ValidationResult.SERVER_ERROR;
		}

		boolean checked = false;
		boolean cannotDownload = false;

		for (String crlDP : crlDistPoints) {
			// Ignorar los URL que contengan la cadena de texto "ocsp":
			if (crlDP.toLowerCase().contains("ocsp")) {
				continue;
			}

			// Descargamos
			byte[] crlBytes;

			try {
				crlBytes = downloadCRL(crlDP);
			} catch (Exception e) {
				logger.severe("No se ha podido descargar la CRL (" + crlDP
						+ "), se continuara con el siguiente punto de distribucion: " + e);
				cannotDownload = true;
				continue;
			}

			X509CRL crl;

			try {
				crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlBytes));
			} catch (Exception e) {
				logger.warning("Error analizando la lista de revocacion: " + e);
				return ValidationResult.SERVER_ERROR;
			}

			// Comprobamos la firma de la CRL
			if (vaPublicKey != null) {
				try {
					crl.verify(vaPublicKey);
				} catch (Exception e) {
					logger.severe("No se ha podido comprobar la firma de la CRL: " + e);
					return ValidationResult.SERVER_ERROR;
				}
			}
			if (crl.isRevoked(cert)) {
				return ValidationResult.REVOKED;
			}

			checked = true;
		}

		if (checked) {
			return ValidationResult.VALID;
		}

		if (cannotDownload) {
			return ValidationResult.CANNOT_DOWNLOAD_CRL;
		}

		return ValidationResult.UNKNOWN;
	}

	private static byte[] downloadCRL(final String crlURL) throws IOException, NamingException, CRLException {
		if (crlURL.startsWith("http://") || crlURL.startsWith("https://")) {
			return downloadCRLFromWeb(crlURL);
		} else if (crlURL.startsWith("ldap://")) {
			return downloadCRLFromLDAP(crlURL);
		} else {
			throw new CRLException("No se soporta el protocolo del punto de distribucion de CRL: " + crlURL);
		}
	}

	private static byte[] downloadCRLFromLDAP(final String ldapURL) throws NamingException {
		Hashtable<String, String> env = new Hashtable<>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapURL);

		Attribute aval = new InitialDirContext(env).getAttributes("").get("certificateRevocationList;binary");
		byte[] val = (byte[]) aval.get();

		if (val == null || val.length == 0) {
			throw new NamingException("No se ha podido descargar la CRL desde " + ldapURL);
		} else {
			return val;
		}
	}

	private static byte[] downloadCRLFromWeb(String url) throws IOException, CRLException {
		HttpClient httpClient = new HttpClient();
		return httpClient.download(url);
	}
}