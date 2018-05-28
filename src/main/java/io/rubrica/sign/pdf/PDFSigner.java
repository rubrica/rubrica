/*
 * Copyright 2009-2018 Rubrica
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

import java.awt.Color;
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
import com.lowagie.text.Font;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfTemplate;

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

	/** Referencia a la &uacute;ltima p&aacute;gina del documento PDF. */
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
	public static final String SIGNATURE_PAGE = "signingPage";
	public static final String LAST_PAGE = "0";
	public static final String FONT_SIZE = "3";
	public static final String TYPE_SIG = "information1";

	static {
		BouncyCastleUtils.initializeBouncyCastle();
	}

        //ETSI TS 102 778-1 V1.1.1 (2009-07)
        //PAdES Basic - Profile based on ISO 32000-1
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
                
		// Tamaño letra
                float fontSize = 3;
                try {
                    if (extraParams.getProperty(FONT_SIZE) == null)
                            fontSize = 3;
                    else
                            fontSize = Float.parseFloat(extraParams.getProperty(FONT_SIZE).trim());
                } catch (final Exception e) {
			logger.warning("Se ha indicado un tamaño de letra invalida ('" + extraParams.getProperty(FONT_SIZE)
					+ "'), se usara el tamaño por defecto: " + fontSize + " " + e);
		}
                
                // Tipo de firma (Información, QR)
		String typeSig = extraParams.getProperty(TYPE_SIG);
                if (typeSig == null)
                    typeSig = "information1";
                
                if (typeSig.equals("QR") && extraParams.getProperty(FONT_SIZE) == null)
                    fontSize = 4.5f;
                
                // Tamaño espaciado
                float fontLeading = fontSize;

		// Pagina donde situar la firma visible
		int page = 0;
		try {
			if (extraParams.getProperty(LAST_PAGE) == null)
				page = 0;
			else
				page = Integer.parseInt(extraParams.getProperty(LAST_PAGE).trim());
		} catch (final Exception e) {
			logger.warning("Se ha indicado un numero de pagina invalido ('" + extraParams.getProperty(LAST_PAGE)
					+ "'), se usara la ultima pagina: " + e);
		}
                
		// Leer el PDF
		PdfReader pdfReader = new PdfReader(data);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		PdfStamper stp;

		try {
			stp = PdfStamper.createSignature(pdfReader, baos, '\0', null, true);
		} catch (DocumentException e) {
			logger.severe("Error al crear la firma para estampar: " + e);
			throw new RubricaException("Error al crear la firma para estampar", e);
		}

		PdfSignatureAppearance sap = stp.getSignatureAppearance();
		sap.setAcro6Layers(true);

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

		if (page == 0 || page < 0 || page > pdfReader.getNumberOfPages())
			page = pdfReader.getNumberOfPages();

		Rectangle signaturePositionOnPage = getSignaturePositionOnPage(extraParams);

		if (signaturePositionOnPage != null) {
			sap.setVisibleSignature(signaturePositionOnPage, page, null);

			X509Certificate x509Certificate = (X509Certificate) certChain[0];
			String informacionCertificado = x509Certificate.getSubjectDN().getName();
			String nombreFirmante = (informacionCertificado.substring(informacionCertificado.lastIndexOf("CN=") + 3,
					informacionCertificado.indexOf(","))).toUpperCase();
			try {
				// Creating the appearance for layer 0
				PdfTemplate pdfTemplate = sap.getLayer(0);
				float width = pdfTemplate.getBoundingBox().getWidth();
				float height = pdfTemplate.getBoundingBox().getHeight();
                                pdfTemplate.rectangle(0, 0, width, height);
                                //Color de fondo
                                //pdfTemplate.setColorFill(Color.LIGHT_GRAY);
                                //pdfTemplate.fill();
                                //Color de fondo
                                switch (typeSig) {
                                    case "QR":{
                                        // Creating the appearance for layer 2
                                        // Nombre Firmante
                                        PdfTemplate pdfTemplate1 = sap.getLayer(2);
                                        Font font1 = new Font(Font.COURIER, fontSize+(fontSize/2), Font.BOLD, Color.BLACK);
                                        Paragraph paragraph1 = new Paragraph(fontLeading, nombreFirmante.trim(), font1);
                                        paragraph1.setAlignment(Paragraph.ALIGN_LEFT);
                                        ColumnText columnText1 = new ColumnText(pdfTemplate1);
                                        columnText1.setSimpleColumn((width / 3) + 1, 0, width, height);
                                        columnText1.addElement(paragraph1);
                                        columnText1.go();
                                        //Imagen
                                        java.awt.image.BufferedImage bufferedImage = null;
                                        //QR
                                        String text = "Nombre firmante: "+nombreFirmante.trim()+"\n";
                                        text = text + "Razón: "+reason+"\n";
                                        text = text + "Fecha firmado: "+signTime+"\n";
                                        try {
                                            bufferedImage = io.rubrica.util.QRCode.generateQR(text, 300, 300);
                                        } catch (Exception e) {
                                            e.printStackTrace();
                                        }
                                        //QR
                                        PdfTemplate pdfTemplateImage = sap.getLayer(2);
                                        ColumnText columnTextImage = new ColumnText(pdfTemplateImage);
                                        columnTextImage.setSimpleColumn(0, 0, (width / 3) - 1, height);
                                        columnTextImage.setAlignment(Paragraph.ALIGN_CENTER);
                                        columnTextImage.addElement(com.lowagie.text.Image.getInstance(bufferedImage, null));
                                        columnTextImage.go();
                                        break;
                                    }
                                    case "information1":{
                                        // Creating the appearance for layer 2
                                        // Nombre Firmante
                                        PdfTemplate pdfTemplate1 = sap.getLayer(2);
                                        Font font1 = new Font(Font.ITALIC, fontSize+(fontSize/2), Font.BOLD, Color.BLACK);
                                        //Font font1 = new Font(Font.ITALIC, 5.0f, Font.BOLD, Color.BLACK);
                                        Paragraph paragraph1 = new Paragraph(nombreFirmante.trim(), font1);
                                        paragraph1.setAlignment(Paragraph.ALIGN_RIGHT);
                                        ColumnText columnText1 = new ColumnText(pdfTemplate1);
                                        columnText1.setSimpleColumn(0, 0, (width / 2) - 1, height);
                                        columnText1.addElement(paragraph1);
                                        columnText1.go();
                                        //Segunda Columna
                                        PdfTemplate pdfTemplate2 = sap.getLayer(2);
                                        Font font2 = new Font(Font.ITALIC, fontSize, Font.NORMAL, Color.DARK_GRAY);
                                        Paragraph paragraph2 = new Paragraph(fontLeading, "Nombre de reconocimiento " + informacionCertificado.trim()
                                                        + "\nRazón: " + reason + "\nFecha: " + signTime, font2);
                                        paragraph2.setAlignment(Paragraph.ALIGN_LEFT);
                                        ColumnText columnText2 = new ColumnText(pdfTemplate2);
                                        columnText2.setSimpleColumn((width / 2) + 1, 0, width, height);
                                        columnText2.addElement(paragraph2);
                                        columnText2.go();
                                        break;
                                    }
                                    case "information2":{
                                        // Creating the appearance for layer 2
                                        //ETSI TS 102 778-6 V1.1.1 (2010-07)
                                        Font font = new Font(Font.HELVETICA, fontSize, Font.NORMAL, Color.BLACK);
                                        com.lowagie.text.pdf.BaseFont baseFont = com.lowagie.text.pdf.BaseFont.createFont();

                                        float x = Float.parseFloat(extraParams.getProperty("PositionOnPageLowerLeftX").trim());
                                        float y = Float.parseFloat(extraParams.getProperty("PositionOnPageLowerLeftY").trim());
                                        nombreFirmante = nombreFirmante.replace(" ", "*");
                                        width = baseFont.getWidthPoint(nombreFirmante, font.getSize());
                                        nombreFirmante = nombreFirmante.replace("*", " ");
                                        height = font.getSize()*2;
                                        sap.setVisibleSignature(new Rectangle(x, y, x+width, y-height), page, null);
                                        pdfTemplate = sap.getLayer(0);
                                        pdfTemplate.rectangle(0, 0, width, height);
                                        PdfTemplate pdfTemplate1 = sap.getLayer(2);
                                        
                                        Paragraph paragraph = new Paragraph(fontLeading, "Firmado digitalmente por:\n", new Font(Font.HELVETICA, fontSize/1.5f, Font.NORMAL, Color.BLACK));
                                        paragraph.add(new Paragraph(fontLeading, nombreFirmante, font));
                                        paragraph.setAlignment(Paragraph.ALIGN_LEFT);
                                        ColumnText columnText = new ColumnText(pdfTemplate1);
                                        columnText.setSimpleColumn(0, 0, width, height);
                                        columnText.addElement(paragraph);
                                        columnText.go();
                                        break;
                                    }
                                    default:{}
                                }
			} catch (DocumentException e) {
				logger.severe("Error al estampar la firma: " + e);
				throw new RubricaException("Error al estampar la firma", e);
			}
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

	private static Rectangle getSignaturePositionOnPage(Properties extraParams) {
		return PdfUtil.getPositionOnPage(extraParams);
	}
}