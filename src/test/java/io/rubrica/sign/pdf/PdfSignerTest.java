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

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.List;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

import io.rubrica.keystore.Alias;
import io.rubrica.keystore.KeyStoreUtilities;
import io.rubrica.sign.SignConstants;
import io.rubrica.sign.SignInfo;
import io.rubrica.sign.Signer;
import io.rubrica.util.BouncyCastleUtils;
import io.rubrica.util.Utils;

public class PdfSignerTest {

	private static final String CERT_PATH = "PRUEBA_FPUBLICO_RARGUELLO.p12";
	private static final String CERT_PASS = "12345678";
	private static final String CERT_ALIAS = "PRUEBA FPUBLICO MARCO RICARDO ARGUELLO JACOME's SECURITY DATA S.A. ID";
	private static final String DATA_FILE = "test1.pdf";

	@Test
	public void testSignPdf() throws Exception {
		PrivateKeyEntry pke = loadKeyEntry(CERT_PATH, CERT_PASS, CERT_ALIAS);
		byte[] pdf = Utils.getDataFromInputStream(ClassLoader.getSystemResourceAsStream(DATA_FILE));
		File tempFile = File.createTempFile("pdfSign", "." + DATA_FILE);
		System.out.println("Temporal para comprobacion manual: " + tempFile.getAbsolutePath());

		Properties params = new Properties();
		params.setProperty("format", SignConstants.SIGN_FORMAT_OOXML);
		params.setProperty("signatureReason", "Comentario : Razon de firma");

		Signer signer = new PDFSigner();

		try (FileOutputStream fos = new FileOutputStream(tempFile)) {
			byte[] result = signer.sign(pdf, SignConstants.SIGN_ALGORITHM_SHA1WITHRSA, pke.getPrivateKey(),
					pke.getCertificateChain(), params);
			fos.write(result);
			fos.flush();
			Assert.assertNotNull(result);
			
			List<SignInfo> firmas = signer.getSigners(result);
			for (SignInfo signInfo : firmas) {
				System.out.println("firma=" + signInfo);
			}
		}
	}

	private static PrivateKeyEntry loadKeyEntry(String certPath, String certPass, String certAlias) throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(ClassLoader.getSystemResourceAsStream(certPath), certPass.toCharArray());

		List<Alias> aliases = KeyStoreUtilities.getSigningAliases(ks);
		for (Alias alias : aliases) {
			System.out.println("alias: " + alias.getAlias());
			System.out.println("name: " + alias.getName());
		}

		return (PrivateKeyEntry) ks.getEntry(certAlias, new KeyStore.PasswordProtection(certPass.toCharArray()));
	}
}
