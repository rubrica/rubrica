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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import org.junit.Test;

import io.rubrica.sign.SignConstants;
import io.rubrica.sign.SignInfo;
import io.rubrica.sign.Signer;
import io.rubrica.sign.TestHelper;

public class PdfVisibleSignatureTest {

//	@Test
	public void testSignPdf() throws Exception {
		File tempFile = File.createTempFile("pdfSign", "." + "test1.pdf");
		System.out.println("Temporal para comprobacion manual: " + tempFile.getAbsolutePath());

		KeyPair kp = TestHelper.createKeyPair();
		Certificate[] chain = TestHelper.createCertificate(kp);

		Path path = Paths.get("/home/rarguello/Documents/diffie.pdf");
		byte[] pdf = Files.readAllBytes(path);

		Properties params = new Properties();
		params.setProperty(PDFSigner.SIGNING_REASON, "Razon de firma");
		params.setProperty(PDFSigner.SIGNING_LOCATION, "Quito, Ecuador");
		params.setProperty(PDFSigner.SIGNATURE_PAGE, "-2");

		params.setProperty(PdfUtil.positionOnPageLowerLeftX, "0");
		params.setProperty(PdfUtil.positionOnPageLowerLeftY, "0");
		params.setProperty(PdfUtil.positionOnPageUpperRightX, "200");
		params.setProperty(PdfUtil.positionOnPageUpperRightY, "100");

		byte[] result;

		try (FileOutputStream fos = new FileOutputStream(tempFile)) {
			Signer signer = new PDFSigner();
			result = signer.sign(pdf, SignConstants.SIGN_ALGORITHM_SHA1WITHRSA, kp.getPrivate(), chain, params);

			assertNotNull(result);
			fos.write(result);
			fos.flush();

			List<SignInfo> firmantes = signer.getSigners(result);
			X509Certificate[] certs = firmantes.get(0).getCerts();
			assertTrue(((X509Certificate) chain[0]).getSerialNumber().equals(certs[0].getSerialNumber()));
		}
	}
}