/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.pdf;

import java.io.ByteArrayOutputStream;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.Document;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfWriter;

import ec.rubrica.keystore.Alias;
import ec.rubrica.keystore.KeyStoreProvider;
import ec.rubrica.keystore.KeyStoreUtilities;
import ec.rubrica.keystore.WindowsKeyStoreProvider;
import ec.rubrica.pdf.tsa.TSAClientBancoCentral;

/**
 * Ejemplo de firma PDF.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
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