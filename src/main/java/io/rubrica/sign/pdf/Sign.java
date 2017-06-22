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

import java.io.ByteArrayOutputStream;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.lowagie.text.Document;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfWriter;

import io.rubrica.keystore.Alias;
import io.rubrica.keystore.KeyStoreProvider;
import io.rubrica.keystore.KeyStoreUtilities;
import io.rubrica.keystore.WindowsKeyStoreProvider;
import io.rubrica.sign.pdf.tsa.TSAClientBancoCentral;

/**
 * Ejemplo de firma PDF.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class Sign {

	public static void main(String[] args) throws Exception {
		AccessController.doPrivileged(new PrivilegedAction<Void>() {
			public Void run() {
				Security.addProvider(new BouncyCastleProvider());
				return null;
			}
		});

		// Create a PDF:
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Document document = new Document();
		PdfWriter.getInstance(document, baos);
		document.open();
		document.add(new Paragraph("Hello World!"));
		document.close();
		byte[] pdf = baos.toByteArray();

		// Sign it!
		KeyStoreProvider keyStoreProvider = new WindowsKeyStoreProvider();
		KeyStore keyStore = keyStoreProvider.getKeystore();
		List<Alias> signingAliases = KeyStoreUtilities
				.getSigningAliases(keyStore);

		int i = 1;

		for (Alias alias : signingAliases) {
			System.out.println("alias=" + alias);
			System.out
					.println("------------------------------------------------------");

			PrivateKey pk = (PrivateKey) keyStore
					.getKey(alias.getAlias(), null);
			Certificate[] chain = keyStore
					.getCertificateChain(alias.getAlias());
			System.out.println("chain.length=" + chain.length);
			byte[] signedPdf = FirmaPDF.firmar(pdf, pk, chain,
					new TSAClientBancoCentral(null));

			// Verificar
			FirmaPDF.verificar(signedPdf);
		}
	}
}