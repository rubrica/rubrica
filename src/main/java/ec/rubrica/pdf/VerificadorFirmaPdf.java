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
import java.security.AccessController;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.KeyStoreUtil;
import com.itextpdf.text.pdf.security.PdfPKCS7;

import ec.rubrica.cert.bce.BceSubCert;
import ec.rubrica.cert.bce.BceSubTestCert;
import ec.rubrica.cert.bce.CertificadoBancoCentralFactory;
import ec.rubrica.cert.securitydata.CertificadoSecurityDataFactory;
import ec.rubrica.cert.securitydata.SecurityDataSubCaCert;
import ec.rubrica.cert.securitydata.old.CertificadoSecurityDataOldFactory;
import ec.rubrica.ocsp.OcspTimeoutException;
import ec.rubrica.ocsp.OcspValidationException;
import ec.rubrica.ocsp.ValidadorOCSP;

/**
 * Verifica una firma digital sobre un documento PDF utilizando iText.
 * 
 * @author Ricardo Arguello (ricardo.arguello@soportelibre.com)
 */
public class VerificadorFirmaPdf {

	/** Campos de un PDF */
	private AcroFields af;

	/** Certificados de CAs del JVM */
	private KeyStore cacerts;

	private static final Logger log = Logger
			.getLogger(VerificadorFirmaPdf.class.getName());

	static {
		AccessController.doPrivileged(new PrivilegedAction<Void>() {
			public Void run() {
				Security.addProvider(new BouncyCastleProvider());
				return null;
			}
		});
	}

	public VerificadorFirmaPdf(byte[] pdf) throws IOException {
		PdfReader pdfReader = new PdfReader(pdf);
		this.af = pdfReader.getAcroFields();
		this.cacerts = KeyStoreUtil.loadCacertsKeyStore();
	}

	public Verificacion verificar() throws OcspValidationException,
			SignatureException {
		int totalRevisiones = af.getTotalRevisions();
		Verificacion verificacion = new Verificacion(totalRevisiones);

		ArrayList<String> nombres = af.getSignatureNames();
		System.out.println("Cuantos nombres=" + nombres.size());

		for (String nombre1 : nombres) {
			System.out.println("nombre=" + nombre1);
			PdfPKCS7 pk = af.verifySignature(nombre1);
			X509Certificate certificadoFirmante = pk.getSigningCertificate();
			log.info("Subject: "
					+ CertificateInfo.getSubjectFields(pk
							.getSigningCertificate()));
			Certificate[] chain = pk.getSignCertificateChain();

			// Verificar OCSP:
			try {
				verificarOscp(certificadoFirmante);
			} catch (OcspTimeoutException e) {
				throw new SignatureException(e);
			}
		}

		for (String nombre : nombres) {
			PdfPKCS7 pk = af.verifySignature(nombre);

			boolean firmaCubreTodoDocumento = af
					.signatureCoversWholeDocument(nombre);

			int revision = af.getRevision(nombre);

			X509Certificate certificadoFirmante = pk.getSigningCertificate();
			log.info("Subject: "
					+ CertificateInfo.getSubjectFields(pk
							.getSigningCertificate()));

			Calendar fechaFirma = pk.getSignDate();
			TimeStampToken tst = pk.getTimeStampToken();

			if (tst != null) {
				log.fine("La firma Tiene Time Stamp");
				fechaFirma = pk.getTimeStampDate();
			}

			boolean selladoTiempoCorrecto = false;

			if (!pk.isTsp() && tst != null) {
				try {
					selladoTiempoCorrecto = pk.verifyTimestampImprint();
				} catch (NoSuchAlgorithmException e) {
					throw new SignatureException(e);
				}
			}

			Certificate[] certificados = pk.getCertificates();

			// TODO: DEBUG
			Certificate[] chain = pk.getSignCertificateChain();
			for (int i = 0; i < chain.length; i++) {
				X509Certificate cert = (X509Certificate) chain[i];
				System.out.println(String.format("[%s] %s", i,
						cert.getSubjectDN()));
				System.out.println(CertificateUtil.getOCSPURL(cert));
			}
			// TODO: DEBUG

			boolean documentoModificado = !pk.verify();

			Firma firma = new Firma(nombre, firmaCubreTodoDocumento, revision,
					certificadoFirmante, fechaFirma, selladoTiempoCorrecto,
					certificados, documentoModificado);

			// TODO: Implementar CRLs
			Collection<CRL> crls = null;

			Object error[] = CertificateVerification.verifyCertificates(
					certificados, cacerts, crls, fechaFirma);

			// TODO: Quitar el mensaje y usar una Enum
			if (error != null) {
				Object objetoConFalla = error[0];
				String mensaje = (String) error[1];

				Falla falla;

				if (objetoConFalla != null) {
					Certificate certConFalla = (Certificate) objetoConFalla;
					falla = new Falla(certConFalla, mensaje);
				} else {
					falla = new Falla(mensaje);
				}

				firma.setFalla(falla);
			}

			verificacion.addFirma(firma);
		}

		return verificacion;
	}

	private void verificarSiTieneOCSP(Certificate[] chain) {
		for (int i = 0; i < chain.length; i++) {
			X509Certificate cert = (X509Certificate) chain[i];
			System.out
					.println(String.format("[%s] %s", i, cert.getSubjectDN()));
			System.out.println(CertificateUtil.getOCSPURL(cert));
		}
	}

	private void verificarOscp(X509Certificate certificado)
			throws OcspTimeoutException, OcspValidationException {

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

		// Validar
		ValidadorOCSP.check(subCert, certificado);
	}

	// iText 5.4.0:
	/*
	 * public void checkRevocation(PdfPKCS7 pkcs7, X509Certificate signCert,
	 * X509Certificate issuerCert, Date date) throws GeneralSecurityException,
	 * IOException { List<BasicOCSPResp> ocsps = new ArrayList<BasicOCSPResp>();
	 * if (pkcs7.getOcsp() != null) ocsps.add(pkcs7.getOcsp()); OCSPVerifier
	 * ocspVerifier = new OCSPVerifier(null, ocsps); List<VerificationOK>
	 * verification = ocspVerifier.verify(signCert, issuerCert, date); if
	 * (verification.size() == 0) { List<X509CRL> crls = new
	 * ArrayList<X509CRL>(); if (pkcs7.getCRLs() != null) { for (CRL crl :
	 * pkcs7.getCRLs()) crls.add((X509CRL) crl); } CRLVerifier crlVerifier = new
	 * CRLVerifier(null, crls); verification.addAll(crlVerifier.verify(signCert,
	 * issuerCert, date)); } if (verification.size() == 0) {
	 * System.out.println("The signing certificate couldn't be verified"); }
	 * else { for (VerificationOK v : verification) System.out.println(v); } }
	 */
}