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

package io.rubrica.ocsp;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import io.rubrica.core.RubricaException;

/**
 * Clase que permite la validacion de un certificado utilizando OCSP.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class ValidadorOCSP {

	private static final Logger logger = Logger.getLogger(ValidadorOCSP.class.getName());

	public void validar(X509Certificate checkCert, X509Certificate rootCert, List<String> urls)
			throws IOException, OcspValidationException, RubricaException {

		for (String url : urls) {
			validar(checkCert, rootCert, url);
		}
	}

	public void validar(X509Certificate checkCert, X509Certificate rootCert, String ocspURL)
			throws IOException, OcspValidationException, RubricaException {

		OCSPReq request;

		try {
			request = generateOCSPRequest(rootCert, checkCert.getSerialNumber());
		} catch (CertificateEncodingException | OperatorCreationException | OCSPException e) {
			throw new RubricaException(e);
		}

		byte[] array = request.getEncoded();

		// Enviar la peticion al servidor OCSP:
		URL url = new URL(ocspURL);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestProperty("Content-Type", "application/ocsp-request");
		con.setRequestProperty("Accept", "application/ocsp-response");
		con.setDoOutput(true);

		OutputStream out = con.getOutputStream();
		DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
		dataOut.write(array);
		dataOut.flush();
		dataOut.close();

		if (con.getResponseCode() / 100 != 2) {
			throw new RubricaException("Respuesta HTTP inválida: " + con.getResponseCode());
		}

		// Get Response
		InputStream in = (InputStream) con.getContent();
		OCSPResp ocspResponse = new OCSPResp(in);

		System.out.println("ocspResponse.getStatus()" + ocspResponse.getStatus());
		if (ocspResponse.getStatus() != 0) {
			throw new RubricaException("Status HTTP inválido: " + ocspResponse.getStatus());
		}

		BasicOCSPResp basicResponse;
		try {
			basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
		} catch (OCSPException e) {
			throw new RubricaException("Problema al decodificar respuesta", e);
		}

		if (basicResponse == null) {
			throw new RubricaException("Respuesta OCSP inválida");
		}

		SingleResp[] responses = basicResponse.getResponses();
		SingleResp response = responses[0];
		CertificateStatus certStatus = response.getCertStatus();

		if (certStatus == CertificateStatus.GOOD) {
			System.out.println("yeah");
			return;
		} else if (certStatus instanceof RevokedStatus) {
			RevokedStatus revokedStatus = (RevokedStatus) certStatus;
			throw new OcspValidationException(revokedStatus.getRevocationReason(), revokedStatus.getRevocationTime());
		} else {
			UnknownStatus unknownStatus = (UnknownStatus) certStatus;
			throw new OcspValidationException();
		}
	}

	private static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
			throws OperatorCreationException, CertificateEncodingException, OCSPException, IOException {
		// Add provider BC
		Provider prov = new BouncyCastleProvider();
		Security.addProvider(prov);

		DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider(prov).build();
		CertificateID id = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
				new JcaX509CertificateHolder(issuerCert), serialNumber);

		// Basic request generation with nonce
		OCSPReqBuilder gen = new OCSPReqBuilder();
		gen.addRequest(id);

		// Add nonce extension
		ExtensionsGenerator extGen = new ExtensionsGenerator();
		byte[] nonce = new byte[16];
		Random rand = new Random();
		rand.nextBytes(nonce);
		extGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce));
		gen.setRequestExtensions(extGen.generate());

		// Build request
		return gen.build();
	}
}