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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfWriter;

import io.rubrica.certificate.ec.bce.CertificadoBancoCentral;
import io.rubrica.certificate.ec.bce.CertificadoBancoCentralFactory;
import io.rubrica.sign.SignInfo;
import io.rubrica.sign.Signer;
import junit.framework.Assert;

public class FirmaPDFTest {

	@Test
	public void firmarPfdTest() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair keypar = gen.generateKeyPair();

		PrivateKey pk = keypar.getPrivate();
		Certificate[] certificate = obtenerCertificado(keypar);
		byte[] pdf = getBytesFromFile(obtenerDocumentoPdf());

		File tempFile = File.createTempFile("test", ".xml");
		System.out.println("Temporal para comprobacion manual: " + tempFile.getAbsolutePath());

		try (final FileOutputStream fos = new FileOutputStream(tempFile);) {
			Signer signer = new PDFSigner();
			byte[] result = signer.sign(pdf, null, pk, certificate, null);
			fos.write(result);
			fos.flush();

			Assert.assertNotNull(result);

			PdfReader reader = new PdfReader(result);
			AcroFields af = reader.getAcroFields();

			ArrayList names = af.getSignatureNames();
			Assert.assertEquals(1, names.size());
			Assert.assertEquals("Signature1", names.get(0));
		}
	}

	private Certificate[] obtenerCertificado(KeyPair keypar) throws IOException, CertificateEncodingException,
			InvalidKeyException, NoSuchProviderException, SignatureException, CertificateException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(X509V1CreateEjemplo.generateV1Certificate(keypar).getEncoded());
		baos.close();

		InputStream in = new ByteArrayInputStream(baos.toByteArray());

		// create the certificate factory
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

		Certificate[] certificate = new Certificate[] { fact.generateCertificate(in) };
		return certificate;
	}

	private File obtenerDocumentoPdf() throws IOException, DocumentException, FileNotFoundException {
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
		while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
			offset += numRead;
		}
		is.close();
		if (offset < bytes.length) {
			throw new IOException("Could not completely read file " + file.getName());
		}
		return bytes;
	}

	public static void main(String[] args) throws Exception {
		byte[] pdf = Files.readAllBytes(Paths.get("/var/tmp/3484.pdf"));
		Signer signer = new PDFSigner();
		List<SignInfo> firmas = signer.getSigners(pdf);

		for (SignInfo firma : firmas) {
			X509Certificate certificado = firma.getCerts()[0];
			CertificadoBancoCentral bce = CertificadoBancoCentralFactory.construir(certificado);
			System.out.println("bce nombre=" + bce.getNombres());
			System.out.println("bce apellidos=" + bce.getPrimerApellido() + " " + bce.getSegundoApellido());
		}
	}
}