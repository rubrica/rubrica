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

import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.junit.Test;

import io.rubrica.util.Utils;

public class VerificadorPdfTest {

	private static final String CERT_PATH = "PRUEBA_FPUBLICO_RARGUELLO.p12";
	private static final String CERT_PASS = "12345678";
	private static final String CERT_ALIAS = "PRUEBA FPUBLICO MARCO RICARDO ARGUELLO JACOME's SECURITY DATA S.A. ID";
	private static final String DATA_FILE = "test1.pdf";

	@Test
	// NEW TEST
	public void test() throws Exception {
		byte[] pdf = Utils.getDataFromInputStream(ClassLoader.getSystemResourceAsStream(DATA_FILE));

		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(ClassLoader.getSystemResourceAsStream(CERT_PATH), CERT_PASS.toCharArray());
		PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS,
				new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));
		Certificate cert = ks.getCertificate(CERT_ALIAS);

		VerificadorFirmaPdf verificador = new VerificadorFirmaPdf(pdf);
		//Verificacion verificacion = verificador.verificar();
		//System.out.println("verificacion= " + verificacion);
		
		verificador.verificarOscp((X509Certificate) cert);
	}
}
