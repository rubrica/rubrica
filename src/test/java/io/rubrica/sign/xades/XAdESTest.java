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

package io.rubrica.sign.xades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
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

import org.junit.Test;

import io.rubrica.sign.pdf.X509V1CreateEjemplo;

public class XAdESTest {

	@Test
	public void firmarPfdTest() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair keypar = gen.generateKeyPair();

		PrivateKey pk = keypar.getPrivate();
		Certificate[] certificate = obtenerCertificado(keypar);
		byte[] xml = "<documento><parrafo>Hola</parrafo></documento>".getBytes();

		File tempFile = File.createTempFile("test", ".xml");
		System.out.println("Temporal para comprobacion manual: " + tempFile.getAbsolutePath());

		try (final FileOutputStream fos = new FileOutputStream(tempFile);) {
			XAdESSigner signer = new XAdESSigner();
			byte[] result = signer.sign(xml, "SHA1withRSA", pk, certificate, null);
			fos.write(result);
			fos.flush();
			
			//List<SimpleSignInfo> firmantes=	signer.getSignersStructure(result);

			//for (SimpleSignInfo simpleSignInfo : firmantes) {
			//	System.out.println(simpleSignInfo.getCerts()[0].getSubjectX500Principal());
			//}
			//Assert.assertNotNull(result);
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
}