package io.rubrica.sign.pdf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.List;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PdfPKCS7;

import io.rubrica.keystore.Alias;
import io.rubrica.keystore.FileKeyStoreProvider;
import io.rubrica.keystore.KeyStoreUtilities;

public class FirmaPdfExterna {

	private static final String PDF = "/var/tmp/pdf.pdf";
	private static final String PDF_SIGNED = "/var/tmp/pdf2.pdf";
	private static final String CERTIFICATE = "/home/rarguello/P0000000478.p12";
	private static final char[] PASSWORD = "ricardo".toCharArray();

	public static void main(String[] args) throws Exception {
		System.out.println("Read PDF");
		byte[] pdf = Files.readAllBytes(Paths.get(PDF));
		FileKeyStoreProvider kp = new FileKeyStoreProvider(CERTIFICATE);
		KeyStore ks = kp.getKeystore(PASSWORD);
		List<Alias> signingAliases = KeyStoreUtilities.getSigningAliases(ks);
		Alias alias = signingAliases.get(0);
		PrivateKey pk = (PrivateKey) ks.getKey(alias.getAlias(), PASSWORD);
		Certificate[] chain = ks.getCertificateChain(alias.getAlias());

		//-------------------------------------------------------------
		System.out.println("Pre Sign");
		PdfReader reader = new PdfReader(pdf);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');
		PdfSignatureAppearance sap = stamper.getSignatureAppearance();
		sap.setReason("Test");
		sap.setLocation("On a server!");
		sap.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
		sap.setCertificate(chain[0]);

		PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
		dic.setReason(sap.getReason());
		dic.setLocation(sap.getLocation());
		dic.setContact(sap.getContact());
		dic.setDate(new PdfDate(sap.getSignDate()));
		sap.setCryptoDictionary(dic);

		HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
		exc.put(PdfName.CONTENTS, new Integer(8192 * 2 + 2));
		sap.preClose(exc);

		ExternalDigest externalDigest = new ExternalDigest() {
			public MessageDigest getMessageDigest(String hashAlgorithm) throws GeneralSecurityException {
				return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
			}
		};

		PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", null, externalDigest, false);
		InputStream data = sap.getRangeStream();
		byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));
		byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, null, null, CryptoStandard.CMS);

		//-------------------------------------------------------------
		System.out.println("Sign");
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(pk);
		sig.update(sh);
		byte[] signedHash = sig.sign();

		//-------------------------------------------------------------
		System.out.println("Post Sign");
		sgn.setExternalDigest(signedHash, null, "RSA");
		byte[] encodedSig = sgn.getEncodedPKCS7(hash, null, null, null, CryptoStandard.CMS);
		byte[] paddedSig = new byte[8192];
		System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);

		PdfDictionary dic2 = new PdfDictionary();
		dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
		
		try {
			sap.close(dic2);
		} catch (DocumentException e) {
			throw new IOException(e);
		}

		System.out.println("Save");
		byte[] signedPdf = baos.toByteArray();
		Files.write(Paths.get(PDF_SIGNED), signedPdf);

		System.out.println("Done");
	}
}