/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.rubrica.sign;

import io.rubrica.validaciones.Documento;
import io.rubrica.keystore.Alias;
import io.rubrica.keystore.FileKeyStoreProvider;
import io.rubrica.keystore.KeyStoreProvider;
import io.rubrica.keystore.KeyStoreUtilities;
import io.rubrica.sign.pdf.PDFSigner;
import io.rubrica.sign.pdf.PdfUtil;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Properties;

/**
 *
 * @author mfernandez
 */
public class Main {	
	public static void main(String args[]) throws KeyStoreException, IOException, Exception {
		String archivo="/home/mfernandez/Firmas/2017/cn=misael_vladimir_fernandez_correa+27112017+sn=0028.p12";
		String password="Password#1";
		
		// La fecha actual en formato ISO-8601 (2017-08-27T17:54:43.562-05:00)
        String fechaHora = ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
		
		String llx="10";//
		String lly="830";//
		String urx=String.valueOf(Integer.parseInt(llx)+110);
		String ury=String.valueOf(Integer.parseInt(lly)-36);
		
		Properties params = new Properties();
        params.setProperty(PDFSigner.SIGNING_LOCATION, "");
		params.setProperty(PDFSigner.SIGNING_REASON, "Firmado digitalmente por FirmaEC");
        params.setProperty(PDFSigner.SIGN_TIME, fechaHora);
        params.setProperty(PDFSigner.LAST_PAGE, "200");
        // Posicion firma
        params.setProperty(PdfUtil.positionOnPageLowerLeftX, llx);
        params.setProperty(PdfUtil.positionOnPageLowerLeftY, lly);
//        params.setProperty(PdfUtil.positionOnPageUpperRightX, urx);
//        params.setProperty(PdfUtil.positionOnPageUpperRightY, ury);
		
		//////Leer PDF:
		String filePdf = "/home/mfernandez/test.pdf";
		byte[] pdf = Documento.loadFile(filePdf);

		KeyStoreProvider ksp = new FileKeyStoreProvider(archivo);
		KeyStore keyStore = ksp.getKeystore(password.toCharArray());

		byte[] signedPdf=null;
		PDFSigner signer = new PDFSigner();
		List<Alias> signingAliases = KeyStoreUtilities.getSigningAliases(keyStore);
        for (Alias alias : signingAliases) {
            PrivateKey key = (PrivateKey) keyStore.getKey(alias.getAlias(), password.toCharArray());
            Certificate[] certChain = keyStore.getCertificateChain(alias.getAlias());
            signedPdf = signer.sign(pdf, "SHA1withRSA", key, certChain, params);
        }
		System.out.println("final firma\n-------");

		//////Permite guardar el archivo en el equipo
		java.io.FileOutputStream fos = new java.io.FileOutputStream(io.rubrica.validaciones.Fichero.ruta());
		fos.write(signedPdf);
		fos.close();
	}
}
