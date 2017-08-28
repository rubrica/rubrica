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
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;

import io.rubrica.core.RubricaException;
import io.rubrica.sign.InvalidFormatException;
import io.rubrica.sign.SignInfo;
import io.rubrica.sign.Signer;
import io.rubrica.util.BouncyCastleUtils;
import io.rubrica.util.Utils;

public class PDFSigner implements Signer {

	private static final String PDF_FILE_HEADER = "%PDF-";
	private static final PdfName PDFNAME_ETSI_RFC3161 = new PdfName("ETSI.RFC3161");
	private static final PdfName PDFNAME_DOCTIMESTAMP = new PdfName("DocTimeStamp");

	private static final Logger logger = Logger.getLogger(PDFSigner.class.getName());

	/**
	 * Razón por la que se realiza la firma.
	 */
	public static final String SIGNING_REASON = "signingReason";

	/**
	 * Localización en la que se realiza la firma.
	 */
	public static final String SIGNING_LOCATION = "signingLocation";

	public static final String SIGN_TIME = "signTime";

	static {
		BouncyCastleUtils.initializeBouncyCastle();
	}

	/**
	 * Algoritmos soportados:
	 * 
	 * <li><i>SHA1withRSA</i></li>
	 * <li><i>SHA256withRSA</i></li>
	 * <li><i>SHA384withRSA</i></li>
	 * <li><i>SHA512withRSA</i></li>
	 */
	@Override
	public byte[] sign(byte[] data, String algorithm, PrivateKey key, Certificate[] certChain, Properties xParams)
			throws RubricaException, IOException {

		Properties extraParams = xParams != null ? xParams : new Properties();

		// Motivo de la firma
		String reason = extraParams.getProperty(SIGNING_REASON);

		// Lugar de realizacion de la firma
		String location = extraParams.getProperty(SIGNING_LOCATION);

		// Fecha y hora de la firma, en formato ISO-8601
		String signTime = extraParams.getProperty(SIGN_TIME);

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

		// Fecha y hora de la firma
		if (signTime != null) {
			Date date = Utils.getSignTime(signTime);
			GregorianCalendar calendar = new GregorianCalendar();
			calendar.setTime(date);
			sap.setSignDate(calendar);
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

	@Override
	public List<SignInfo> getSigners(byte[] sign) throws InvalidFormatException, IOException {
		if (!isPdfFile(sign)) {
			throw new InvalidFormatException("El archivo no es un PDF");
		}

		PdfReader pdfReader;

		try {
			pdfReader = new PdfReader(sign);
		} catch (Exception e) {
			logger.severe("No se ha podido leer el PDF: " + e);
			throw new InvalidFormatException("No se ha podido leer el PDF", e);
		}

		AcroFields af;

		try {
			af = pdfReader.getAcroFields();
		} catch (Exception e) {
			logger.severe(
					"No se ha podido obtener la informacion de los firmantes del PDF, se devolvera un arbol vacio: "
							+ e);
			throw new InvalidFormatException("No se ha podido obtener la informacion de los firmantes del PDF", e);
		}

		@SuppressWarnings("unchecked")
		List<String> names = af.getSignatureNames();

		Object pkcs1Object = null;
		List<SignInfo> signInfos = new ArrayList<>();

		for (String signatureName : names) {
			// Comprobamos si es una firma o un sello
			PdfDictionary pdfDictionary = af.getSignatureDictionary(signatureName);

			if (PDFNAME_ETSI_RFC3161.equals(pdfDictionary.get(PdfName.SUBFILTER))
					|| PDFNAME_DOCTIMESTAMP.equals(pdfDictionary.get(PdfName.SUBFILTER))) {
				// Ignoramos los sellos
				continue;
			}

			PdfPKCS7 pcks7;

			try {
				pcks7 = af.verifySignature(signatureName);
			} catch (Exception e) {
				e.printStackTrace();
				logger.severe("El PDF contiene una firma corrupta o con un formato desconocido (" + signatureName
						+ "), se continua con las siguientes si las hubiese: " + e);
				continue;
			}

			Certificate[] signCertificateChain = pcks7.getSignCertificateChain();
			X509Certificate[] certChain = new X509Certificate[signCertificateChain.length];

			for (int i = 0; i < certChain.length; i++) {
				certChain[i] = (X509Certificate) signCertificateChain[i];
			}

			SignInfo signInfo = new SignInfo(certChain, pcks7.getSignDate().getTime());

			// Extraemos el PKCS1 de la firma
			try {
				// iText antiguo
				Field digestField = Class.forName("com.lowagie.text.pdf.PdfPKCS7").getDeclaredField("digest");
				digestField.setAccessible(true);
				pkcs1Object = digestField.get(pcks7);

				if (pkcs1Object instanceof byte[]) {
					signInfo.setPkcs1((byte[]) pkcs1Object);
				}
			} catch (Exception e) {
				e.printStackTrace();
				logger.severe(
						"No se ha podido obtener informacion de una de las firmas del PDF, se continuara con la siguiente: "
								+ e);
				continue;
			}

			signInfos.add(signInfo);
		}

		return signInfos;
	}

	private boolean isPdfFile(final byte[] data) {

		byte[] buffer = new byte[PDF_FILE_HEADER.length()];

		try {
			new ByteArrayInputStream(data).read(buffer);
		} catch (Exception e) {
			buffer = null;
		}

		// Comprobamos que cuente con una cabecera PDF
		if (buffer != null && !PDF_FILE_HEADER.equals(new String(buffer))) {
			return false;
		}

		try {
			// Si lanza una excepcion al crear la instancia, no es un fichero
			// PDF
			new PdfReader(data);
		} catch (final Exception e) {
			return false;
		}

		return true;
	}
}