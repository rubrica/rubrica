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
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.logging.Logger;

import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;

import io.rubrica.core.RubricaException;
import io.rubrica.sign.Signer;

public class PDFSigner implements Signer {

	private static final Logger logger = Logger.getLogger(PDFSigner.class.getName());

	/**
	 * Razón por la que se realiza la firma.
	 */
	public static final String SIGNING_REASON = "signingReason";

	/**
	 * Localización en la que se realiza la firma.
	 */
	public static final String SIGNING_LOCATION = "signingLocation";

	/**
	 * Algoritmos soportados:
	 * 
	 *  <li><i>SHA1withRSA</i></li>
     *  <li><i>SHA256withRSA</i></li>
     *  <li><i>SHA384withRSA</i></li>
     *  <li><i>SHA512withRSA</i></li>
	 */
	@Override
	public byte[] sign(byte[] data, String algorithm, PrivateKey key, Certificate[] certChain, Properties xParams)
			throws RubricaException, IOException {

		Properties extraParams = xParams != null ? xParams : new Properties();

		// Motivo de la firma
		String reason = extraParams.getProperty(SIGNING_REASON);

		// Lugar de realizacion de la firma
		String location = extraParams.getProperty(SIGNING_LOCATION);

		// Leer el PDF
		PdfReader pdfReader = new PdfReader(data);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		PdfStamper stp;

		try {
			stp = PdfStamper.createSignature(pdfReader, baos, '\0');
		} catch (DocumentException e) {
			logger.severe("Error al crear la firma para estampar: " + e);
			throw new RubricaException("Error al crear la firma para estampar", e);
		}

		PdfSignatureAppearance sap = stp.getSignatureAppearance();

		// Razon de firma
		if (reason != null) {
			sap.setReason(reason);
		}

		// Localizacion en donde se produce la firma
		if (location != null) {
			sap.setLocation(location);
		}

		sap.setCrypto(key, (X509Certificate) certChain[0], null, PdfSignatureAppearance.WINCER_SIGNED);

		try {
			stp.close();
		} catch (DocumentException e) {
			logger.severe("Error al estampar la firma: " + e);
			throw new RubricaException("Error al estampar la firma", e);
		}

		return baos.toByteArray();
	}
}