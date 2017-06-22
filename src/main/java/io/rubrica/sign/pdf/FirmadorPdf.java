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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.lowagie.text.pdf.TSAClient;

/**
 * Clase para firmar archivos PDF.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 * @deprecated
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

	/*
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
	*/
}