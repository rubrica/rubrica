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
import java.io.IOException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;

/**
 * Clase para firmar archivos PDF.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class FirmadorPdf {

	private byte[] pdf;
	private TSAClient tsaClient;

	static {
		AccessController.doPrivileged(new PrivilegedAction<Void>() {
			public Void run() {
				Security.addProvider(new BouncyCastleProvider());
				return null;
			}
		});
	}

	public FirmadorPdf(byte[] pdf) {
		this.pdf = pdf;
		this.tsaClient = null;
	}

	public FirmadorPdf(byte[] pdf, TSAClient tsaClient) {
		this.pdf = pdf;
		this.tsaClient = tsaClient;
	}

	public byte[] firmar(PrivateKey pk, X509Certificate certificado,
			String razon, String ubicacion) throws IOException {
		try {
			// Creating the reader and the stamper
			PdfReader reader = new PdfReader(pdf);

			ByteArrayOutputStream signedPdf = new ByteArrayOutputStream();
			PdfStamper stamper = PdfStamper.createSignature(reader, signedPdf,
					'\0');

			// Creating the appearance
			PdfSignatureAppearance appearance = stamper
					.getSignatureAppearance();
			appearance.setReason(razon);
			appearance.setLocation(ubicacion);

			Rectangle pageSize = reader.getPageSize(1);
			Rectangle position = new Rectangle(15, pageSize.getHeight() - 50,
					250, pageSize.getHeight());
			appearance.setVisibleSignature(position, 1, "sig");

			// Creating the signature
			ExternalSignature pks = new PrivateKeySignature(pk,
					DigestAlgorithms.SHA1, null);

			Certificate[] chain = new Certificate[] { certificado };

			MakeSignature.signDetached(appearance, pks, chain, null, null,
					tsaClient, BouncyCastleProvider.PROVIDER_NAME, 0,
					MakeSignature.CMS);

			return signedPdf.toByteArray();
		} catch (DocumentException e) {
			throw new RuntimeException(e);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}
}