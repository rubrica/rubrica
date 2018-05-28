/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.rubrica.sign;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Properties;

import javax.swing.JOptionPane;

import io.rubrica.core.RubricaException;
import io.rubrica.keystore.Alias;
import io.rubrica.keystore.KeyStoreProviderFactory;
import io.rubrica.keystore.KeyStoreUtilities;
import io.rubrica.sign.pdf.PDFSigner;
import io.rubrica.sign.pdf.PdfUtil;
import io.rubrica.validaciones.Documento;

/**
 *
 * @author mfernandez
 */
public class Main {

	public static void main(String args[]) throws KeyStoreException, IOException, Exception {
		////// VERIFICAR
		// String fileP7m = "/home/mfernandez/Decretos firmados/1.pdf.p7m";
		// byte[] p7m = Documento.loadFile(fileP7m);
		//
		// VerificadorCMS verificadorCMS = new VerificadorCMS();
		// byte[] signedP7m = verificadorCMS.verify(p7m);
		//
		// java.io.FileOutputStream fosP7m = new
		////// java.io.FileOutputStream(io.rubrica.validaciones.Fichero.ruta());
		// fosP7m.write(signedP7m);
		// fosP7m.close();
		////// VERIFICAR

		// ARCHIVO
		// String archivo="/Volumes/PERSONAL/misael_vladimir_fernandez_correa.p12";
		// String password="1234";
		// TOKEN
		String password = "1234";

		// La fecha actual en formato ISO-8601 (2017-08-27T17:54:43.562-05:00)
		String fechaHora = ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

		String llx = "10";
		String lly = "830";
		String urx = String.valueOf(Integer.parseInt(llx) + 110);
		String ury = String.valueOf(Integer.parseInt(lly) - 36);

		Properties params = new Properties();
		params.setProperty(PDFSigner.SIGNING_LOCATION, "");
		params.setProperty(PDFSigner.SIGNING_REASON, "Firmado digitalmente por FirmaEC");
		params.setProperty(PDFSigner.SIGN_TIME, fechaHora);
		params.setProperty(PDFSigner.LAST_PAGE, "200");
		// Posicion firma
		params.setProperty(PdfUtil.positionOnPageLowerLeftX, llx);
		params.setProperty(PdfUtil.positionOnPageLowerLeftY, lly);
		// params.setProperty(PdfUtil.positionOnPageUpperRightX, urx);
		// params.setProperty(PdfUtil.positionOnPageUpperRightY, ury);

		////// LEER PDF:
		// String filePdf = "C:\\Users\\Desarrollo\\Desktop\\test.pdf";
		String filePdf = "/Users/test/Downloads/Manual-Usuario-FirmaEC.pdf";
		byte[] pdf = Documento.loadFile(filePdf);

		// ARCHIVO
		// KeyStoreProvider ksp = new FileKeyStoreProvider(archivo);
		// KeyStore keyStore = ksp.getKeystore(password.toCharArray());
		// TOKEN
		KeyStore keyStore = KeyStoreProviderFactory.getKeyStore(password);

		byte[] signedPdf = null;
		PDFSigner signer = new PDFSigner();
		String alias = seleccionarAlias(keyStore);
		PrivateKey key = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
		Certificate[] certChain = keyStore.getCertificateChain(alias);
		signedPdf = signer.sign(pdf, "SHA1withRSA", key, certChain, params);
		System.out.println("final firma\n-------");
		////// Permite guardar el archivo en el equipo
		java.io.FileOutputStream fos = new java.io.FileOutputStream(io.rubrica.validaciones.Fichero.ruta());
		fos.write(signedPdf);
		fos.close();
	}

	public static String seleccionarAlias(KeyStore keyStore) throws RubricaException {
		String aliasString = null;
		// Con que certificado firmar?
		List<Alias> signingAliases = KeyStoreUtilities.getSigningAliases(keyStore);

		if (signingAliases.isEmpty()) {
			throw new RubricaException("No se encontró un certificado para firmar");
		}

		if (signingAliases.size() == 1) {
			aliasString = signingAliases.get(0).getAlias();
		} else {
			Alias alias = (Alias) JOptionPane.showInputDialog(null, "Escoja...", "Certificado para firmar",
					JOptionPane.QUESTION_MESSAGE, null, signingAliases.toArray(), signingAliases.get(0));
			if (alias != null) {
				aliasString = alias.getAlias();
			}
		}
		return aliasString;
	}
}