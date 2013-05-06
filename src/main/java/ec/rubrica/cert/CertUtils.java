/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;

/**
 * Utilidades para trabajar con Certificados.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class CertUtils {

	public static String getExtensionValue(X509Certificate certificate,
			String oid) throws IOException {
		String decoded = null;
		byte[] extensionValue = certificate.getExtensionValue(oid);

		if (extensionValue != null) {
			ASN1Primitive derObject = toDERObject(extensionValue);
			if (derObject instanceof DEROctetString) {
				DEROctetString derOctetString = (DEROctetString) derObject;
				derObject = toDERObject(derOctetString.getOctets());
				if (derObject instanceof ASN1String) {
					ASN1String s = (ASN1String) derObject;
					decoded = s.getString();
				}
			}
		}
		return decoded;
	}

	private static ASN1Primitive toDERObject(byte[] data) throws IOException {
		ByteArrayInputStream inStream = new ByteArrayInputStream(data);
		ASN1InputStream asnInputStream = null;

		try {
			asnInputStream = new ASN1InputStream(inStream);
			return asnInputStream.readObject();
		} finally {
			if (asnInputStream != null) {
				try {
					asnInputStream.close();
				} catch (IOException ignore) {
				}
			}
		}
	}
}