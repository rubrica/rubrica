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

package io.rubrica.sign;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfWriter;

public class TestHelper {

	public static KeyPair createKeyPair() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		return gen.generateKeyPair();
	}

	public static Certificate[] createCertificate(KeyPair keypar) throws Exception {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			baos.write(generateV1Certificate(keypar).getEncoded());

			try (InputStream in = new ByteArrayInputStream(baos.toByteArray())) {
				CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
				return new Certificate[] { fact.generateCertificate(in) };
			}
		}
	}

	public static byte[] crearPdf() throws Exception {
		File tempFile = File.createTempFile("temp-", ".pdf");

		Document document = new Document();
		PdfWriter.getInstance(document, new FileOutputStream(tempFile));
		document.open();

		Paragraph paragraph = new Paragraph("Esto es una prueba");
		paragraph.setAlignment(Element.ALIGN_RIGHT);
		document.add(paragraph);
		document.close();

		return Files.readAllBytes(tempFile.toPath());
	}

	public static X509Certificate generateV1Certificate(KeyPair pair)
			throws InvalidKeyException, NoSuchProviderException, SignatureException {
		BouncyCastleProvider prov = new BouncyCastleProvider();
		Security.addProvider(prov);

		// generate the certificate
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
		certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		return certGen.generateX509Certificate(pair.getPrivate());
	}
}