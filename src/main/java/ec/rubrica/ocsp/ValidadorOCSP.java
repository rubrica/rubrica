/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.ocsp;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.itextpdf.text.pdf.security.CertificateUtil;

import ec.rubrica.util.BouncyCastleUtils;

/**
 * Clase que permite la validacion de un certificado utilizando OCSP.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class ValidadorOCSP {

	private static final Logger logger = Logger.getLogger(ValidadorOCSP.class
			.getName());

	static {
		BouncyCastleUtils.initializeBouncyCastle();
	}

	public static void check(X509Certificate issuerCert,
			X509Certificate x509Cert) throws OcspValidationException,
			OcspTimeoutException {
		try {
			BigInteger serialNumber = x509Cert.getSerialNumber();
			X509CertificateHolder holder;

			try {
				holder = new X509CertificateHolder(issuerCert.getEncoded());
			} catch (IOException e) {
				throw new RuntimeException(e);
			}

			CertificateID id = new CertificateID(
					new JcaDigestCalculatorProviderBuilder()
							.setProvider(BouncyCastleProvider.PROVIDER_NAME)
							.build().get(CertificateID.HASH_SHA1), holder,
					serialNumber);

			OCSPReqBuilder ocspGen = new OCSPReqBuilder();
			ocspGen.addRequest(id);
			OCSPReq ocspReq = ocspGen.build();

			// Ir al OCSP
			String ocspUrl = CertificateUtil.getOCSPURL(x509Cert);

			if (ocspUrl == null) {
				logger.info("URL de OCSP is null");
				return;
			}

			URL url;

			try {
				url = new URL(ocspUrl);
			} catch (MalformedURLException e) {
				throw new RuntimeException(e);
			}

			HttpURLConnection con;
			OCSPResp ocspResponse;

			try {
				con = (HttpURLConnection) url.openConnection();

				con.setRequestProperty("Content-Type",
						"application/ocsp-request");
				con.setRequestProperty("Accept", "application/ocsp-response");
				con.setDoOutput(true);

				OutputStream out = con.getOutputStream();
				DataOutputStream dataOut = new DataOutputStream(
						new BufferedOutputStream(out));
				dataOut.write(ocspReq.getEncoded());

				dataOut.flush();
				dataOut.close();

				/*
				 * Se parsea la respuesta y se obtiene el estado del certificado
				 * retornado por el OCSP
				 */
				InputStream in = (InputStream) con.getContent();
				byte[] resp = read(in); // Read the reponse
				ocspResponse = new OCSPResp(resp);
			} catch (IOException e) {
				throw new OcspTimeoutException(url);
			}

			int status = ocspResponse.getStatus();
			System.out.println("status=" + status);

			BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse
					.getResponseObject();

			if (basicResponse != null) {
				SingleResp[] responses = basicResponse.getResponses();
				SingleResp response = responses[0];
				CertificateStatus certStatus = response.getCertStatus();

				if (certStatus instanceof RevokedStatus) {
					System.out.println("REVOKED");
					RevokedStatus revokedStatus = (RevokedStatus) certStatus;
					System.out.println("Reason: "
							+ revokedStatus.getRevocationReason());
					System.out.println("Date: "
							+ revokedStatus.getRevocationTime());

					throw new OcspValidationException(
							revokedStatus.getRevocationReason(),
							revokedStatus.getRevocationTime());
				}
			}
		} catch (OCSPException e) {
			throw new RuntimeException(e);
		} catch (CertificateEncodingException e) {
			throw new RuntimeException(e);
		} catch (OperatorCreationException e) {
			throw new RuntimeException(e);
		}
	}

	private static byte[] read(InputStream in) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int next = in.read();
		while (next > -1) {
			bos.write(next);
			next = in.read();
		}
		bos.flush();
		return bos.toByteArray();
	}
}