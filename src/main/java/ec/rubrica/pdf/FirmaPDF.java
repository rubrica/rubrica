/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.pdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.logging.Logger;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.KeyStoreUtil;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;

import ec.rubrica.cert.securitydata.SecurityDataSubCaCert;

/**
 * Clase para firmar documentos PDF usando la libreria iText.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class FirmaPDF {

	private static final Logger logger = Logger.getLogger(FirmaPDF.class
			.getName());

	public static byte[] firmar(byte[] pdf, PrivateKey pk, Certificate[] chain,
			TSAClient tsaClient) throws IOException {
		try {
			// Creating the reader and the stamper
			PdfReader reader = new PdfReader(pdf);
			ByteArrayOutputStream signedPdf = new ByteArrayOutputStream();
			PdfStamper stamper = PdfStamper.createSignature(reader, signedPdf,
					'\0');

			// Creating the appearance
			PdfSignatureAppearance appearance = stamper
					.getSignatureAppearance();
			appearance.setReason("Testing");
			appearance.setLocation("Quito");
			appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1,
					"sig");

			// Creating the signature
			PrivateKeySignature pks = new PrivateKeySignature(pk,
					DigestAlgorithms.SHA1, null);

			OcspClient ocsp = new OcspClientBouncyCastle();

			MakeSignature.signDetached(appearance, pks, chain, null, ocsp,
					tsaClient, BouncyCastleProvider.PROVIDER_NAME, 0,
					MakeSignature.CMS);

			return signedPdf.toByteArray();
		} catch (DocumentException e) {
			throw new RuntimeException(e);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * TODO: Mas de dos firmas?
	 * 
	 * @param pdf
	 * @throws IOException
	 * @throws SignatureException
	 */
	public static boolean verificar(byte[] pdf) throws IOException,
			SignatureException {

		PdfReader reader = new PdfReader(pdf);
		AcroFields af = reader.getAcroFields();
		ArrayList<String> names = af.getSignatureNames();

		for (int k = 0; k < names.size(); ++k) {
			String name = (String) names.get(k);
			System.out.println("Signature name: " + name);
			System.out.println("Signature covers whole document: "
					+ af.signatureCoversWholeDocument(name));
			System.out.println("Document revision: " + af.getRevision(name)
					+ " of " + af.getTotalRevisions());

			PdfPKCS7 pk = af.verifySignature(name);
			Calendar cal = pk.getSignDate();
			Certificate[] pkc = pk.getCertificates();
			TimeStampToken ts = pk.getTimeStampToken();

			if (ts != null) {
				cal = pk.getTimeStampDate();
			}

			if (!pk.isTsp() && ts != null) {
				boolean impr;
				try {
					impr = pk.verifyTimestampImprint();
					System.out.println("Timestamp imprint verifies: " + impr);
					System.out.println("Timestamp date: " + cal);
				} catch (NoSuchAlgorithmException e) {
					throw new SignatureException(e);
				}
			}

			System.out.println("Subject: "
					+ CertificateInfo.getSubjectFields(pk
							.getSigningCertificate()));
			System.out.println("Document modified: " + !pk.verify());

			KeyStore kall = KeyStoreUtil.loadCacertsKeyStore();

			Object fails[] = CertificateVerification.verifyCertificates(pkc,
					kall, null, cal);

			if (fails == null) {
				System.out
						.println("Certificates verified against the KeyStore");
			} else {
				System.out.println("Certificate failed: " + fails[0]);
				return false;
			}

			BasicOCSPResp ocsp = pk.getOcsp();

			if (ocsp != null) {
				try {
					X509Certificate cert = new SecurityDataSubCaCert();

					boolean verifies = ocsp
							.isSignatureValid(new JcaContentVerifierProviderBuilder()
									.setProvider(
											BouncyCastleProvider.PROVIDER_NAME)
									.build(cert.getPublicKey()));

					System.out.println("OCSP signature verifies: " + verifies);

					System.out
							.println("OCSP revocation refers to this certificate: "
									+ pk.isRevocationValid());

					return verifies;
				} catch (OperatorCreationException e) {
					throw new SignatureException(e);
				} catch (OCSPException e) {
					throw new SignatureException(e);
				}
			} else {
				return true;
			}
		}

		return false;
	}
}