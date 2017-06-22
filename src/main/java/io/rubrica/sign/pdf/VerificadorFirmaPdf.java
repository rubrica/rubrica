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
import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;

import io.rubrica.certificate.ec.bce.BceCaTestCert;
import io.rubrica.certificate.ec.bce.BceSubCert;
import io.rubrica.certificate.ec.bce.CertificadoBancoCentralFactory;
import io.rubrica.certificate.ec.securitydata.CertificadoSecurityDataFactory;
import io.rubrica.certificate.ec.securitydata.SecurityDataSubCaCert;
import io.rubrica.certificate.ec.securitydata.old.CertificadoSecurityDataOldFactory;
import io.rubrica.core.RubricaException;
import io.rubrica.ocsp.OcspValidationException;
import io.rubrica.ocsp.ValidadorOCSP;
import io.rubrica.sign.Verificacion;
import io.rubrica.util.CertificateUtils;

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

	private static final Logger log = Logger.getLogger(VerificadorFirmaPdf.class.getName());

	static {
		AccessController.doPrivileged(new PrivilegedAction<Void>() {
			public Void run() {
				Security.addProvider(new BouncyCastleProvider());
				return null;
			}
		});
	}

	public VerificadorFirmaPdf(byte[] pdf) throws IOException, KeyStoreException {
		PdfReader pdfReader = new PdfReader(pdf);
		this.af = pdfReader.getAcroFields();
		// this.cacerts = KeyStoreUtil.loadCacertsKeyStore();

		// BCE:
		// KeyStore.Entry bce = new KeyStore.TrustedCertificateEntry(new
		// BceCaCert());
		// cacerts.setEntry("bce", bce, null);
		// KeyStore.Entry bceTest = new KeyStore.TrustedCertificateEntry(new
		// BceCaTestCert());
		// cacerts.setEntry("bce", bceTest, null);
	}

	public Verificacion verificar() throws IOException, OcspValidationException, SignatureException {
		int totalRevisiones = af.getTotalRevisions();
		Verificacion verificacion = new Verificacion(totalRevisiones);

		ArrayList<String> nombres = af.getSignatureNames();
		System.out.println("Cuantos nombres=" + nombres.size());

		for (String nombre : nombres) {
			System.out.println("nombre=" + nombre);
			PdfPKCS7 pk = af.verifySignature(nombre);

			Certificate[] chain = pk.getSignCertificateChain();
			X509Certificate certificado = pk.getSigningCertificate();

			// Verificar OCSP:
			try {
				System.out.println("Verificando OCSP");
				verificarOscp(certificado);
				System.out.println(" OCSP OK");
			} catch (RubricaException e) {
				throw new SignatureException(e);
			}

			boolean firmaCubreTodoDocumento = af.signatureCoversWholeDocument(nombre);
			int revision = af.getRevision(nombre);

			X509Certificate certificadoFirmante = pk.getSigningCertificate();

			Calendar fechaFirma = pk.getSignDate();
			TimeStampToken tst = pk.getTimeStampToken();

			if (tst != null) {
				log.warning("La firma Tiene Time Stamp");
				fechaFirma = pk.getTimeStampDate();
			}

			boolean selladoTiempoCorrecto = false;

			// if (!pk.isTsp() && tst != null) {
			// try {
			// selladoTiempoCorrecto = pk.verifyTimestampImprint();
			// } catch (NoSuchAlgorithmException e) {
			// throw new SignatureException(e);
			// }
			// }

			for (int i = 0; i < chain.length; i++) {
				X509Certificate cert = (X509Certificate) chain[i];
				System.out.println(String.format("[%s] %s", i, cert.getSubjectDN()));
				// System.out.println(CertificateUtil.getOCSPURL(cert));
			}

			List<String> ocspUrls;

			try {
				ocspUrls = CertificateUtils.getCrlDistributionPoints(certificadoFirmante);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}

			boolean documentoModificado = !pk.verify();

			Firma firma = new Firma(nombre, firmaCubreTodoDocumento, revision, certificadoFirmante, fechaFirma,
					selladoTiempoCorrecto, chain, documentoModificado);

			// TODO: Implementar CRLs
			Collection<CRL> crls = null;

			// Object error[] =
			// CertificateVerification.verifyCertificates(certificados, cacerts,
			// crls, fechaFirma);
			/*
			 * // TODO: Quitar el mensaje y usar una Enum if (error != null) {
			 * Object objetoConFalla = error[0]; String mensaje = (String)
			 * error[1];
			 * 
			 * Falla falla;
			 * 
			 * if (objetoConFalla != null) { Certificate certConFalla =
			 * (Certificate) objetoConFalla; falla = new Falla(certConFalla,
			 * mensaje); } else { falla = new Falla(mensaje); }
			 * 
			 * firma.setFalla(falla); }
			 */
			verificacion.addFirma(firma);
		}

		return verificacion;
	}

	private void verificarSiTieneOCSP(Certificate[] chain) {
		for (int i = 0; i < chain.length; i++) {
			X509Certificate cert = (X509Certificate) chain[i];
			System.out.println(String.format("[%s] %s", i, cert.getSubjectDN()));
			// System.out.println(CertificateUtil.getOCSPURL(cert));
		}
	}

	public void verificarOscp(X509Certificate certificado)
			throws IOException, OcspValidationException, RubricaException {

		// Validar
		ValidadorOCSP validadorOCSP = new ValidadorOCSP();

		X509Certificate rootCert = null;

		// TODO: Factory
		if (CertificadoSecurityDataFactory.esCertificadoDeSecurityData(certificado)
				|| CertificadoSecurityDataOldFactory.esCertificadoDeSecurityDataOld(certificado)) {
			rootCert = new SecurityDataSubCaCert();

			List<String> urls = CertificateUtils.getAuthorityInformationAccess(certificado);
			validadorOCSP.validar(certificado, rootCert, urls);
		} else if (CertificadoBancoCentralFactory.esCertificadoDelBancoCentral(certificado)) {
			if (CertificadoBancoCentralFactory.estTestCa(certificado)) {
				System.out.println("BCE Test CA");
				rootCert = new BceCaTestCert();
			} else {
				rootCert = new BceSubCert();
				System.out.println("BCE Root CA");
			}

			String url = "http://ocsp.eci.bce.ec/ejbca/publicweb/status/ocsp";
			//validadorOCSP.validar(certificado, rootCert, url);
		}
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