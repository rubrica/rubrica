package ec.rubrica.test.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;

import junit.framework.Assert;

import org.junit.Test;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Element;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfWriter;

import ec.rubrica.pdf.FirmaPDF;

public class FirmaPDFTest {

	@Test
	public void firmarPfdTest() throws NoSuchAlgorithmException,
			NoSuchProviderException, CertificateException, DocumentException,
			IOException, InvalidKeyException, SignatureException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair keypar = gen.generateKeyPair();
		PrivateKey pk = keypar.getPrivate();

		Certificate[] certificate = obtenerCertificado(keypar);

		File tempFile = obtenerDocumentoPdf();
		
		byte[] archivoFirmado = FirmaPDF.firmar(getBytesFromFile(tempFile), pk,
				certificate, null);
		
		PdfReader reader = new PdfReader(archivoFirmado);
		AcroFields af = reader.getAcroFields();
 
		ArrayList<String> names = af.getSignatureNames();
		Assert.assertEquals(1, names.size());
		Assert.assertEquals("sig", names.get(0));
	}

	private Certificate[] obtenerCertificado(KeyPair keypar)
			throws IOException, CertificateEncodingException,
			InvalidKeyException, NoSuchProviderException, SignatureException,
			CertificateException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		bOut.write(X509V1CreateEjemplo.generateV1Certificate(keypar)
				.getEncoded());

		bOut.close();

		InputStream in = new ByteArrayInputStream(bOut.toByteArray());

		// create the certificate factory
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

		Certificate[] certificate = new Certificate[] { fact.generateCertificate(in) };
		return certificate;
	}

	private File obtenerDocumentoPdf() throws IOException, DocumentException,
			FileNotFoundException {
		File tempFile = File.createTempFile("temp-file-name", ".tmp");

		Document document = new Document();
		PdfWriter.getInstance(document, new FileOutputStream(tempFile));
		document.open();
		Paragraph paragraph = new Paragraph("Esto es una prueba");
		paragraph.setAlignment(Element.ALIGN_RIGHT);
		document.add(paragraph);

		document.close();
		return tempFile;
	}

	private static byte[] getBytesFromFile(File file) throws IOException {
		InputStream is = new FileInputStream(file);
		long length = file.length();
		byte[] bytes = new byte[(int) length];
		int offset = 0;
		int numRead = 0;
		while (offset < bytes.length
				&& (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
			offset += numRead;
		}
		is.close();
		if (offset < bytes.length) {
			throw new IOException("Could not completely read file "
					+ file.getName());
		}
		return bytes;
	}

}
