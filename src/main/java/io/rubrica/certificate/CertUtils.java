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

package io.rubrica.certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Utilidades para trabajar con Certificados.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class CertUtils {

	public static String getExtensionValueSubjectAlternativeNames(X509Certificate certificate, String oid)
			throws IOException {
		return getSubjectAlternativeName(certificate, oid);
	}

	public static String getSubjectAlternativeName(X509Certificate certificate, String oid) {
		String decoded = null;
		try {
			Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
			if (altNames == null)
				return decoded;
			for (List<?> item : altNames) {
				Integer type = (Integer) item.get(0);
				if (type == 0) {
					// Type OtherName found so return the associated value
					try {
						// Value is encoded using ASN.1 so decode it to get the
						// server's identity
						ASN1InputStream decoder = new ASN1InputStream((byte[]) item.get(1));
						Object object = decoder.readObject();
						ASN1Sequence otherNameSeq = null;
						if (object != null && object instanceof ASN1Sequence) {
							otherNameSeq = (ASN1Sequence) object;
							// Check the object identifier
							ASN1ObjectIdentifier objectId = (ASN1ObjectIdentifier) otherNameSeq.getObjectAt(0);
							if (objectId.toString().equals(oid)) {
								DERTaggedObject objectDetail = ((DERTaggedObject) otherNameSeq.getObjectAt(1));
								decoded = objectDetail.getObject().toASN1Primitive().toString();
								decoded = decoded.substring(3);
								break;
							}
						} else if (object != null && object instanceof DERTaggedObject) {
							DERTaggedObject derTaggedObject = (DERTaggedObject) object;
							Object obj = derTaggedObject.getObject();
							if (obj != null && obj instanceof ASN1Sequence) {
								otherNameSeq = (ASN1Sequence) obj;
								// Check the object identifier
								ASN1ObjectIdentifier objectId = (ASN1ObjectIdentifier) otherNameSeq.getObjectAt(0);
								if (objectId.toString().equals(oid)) {
									DERTaggedObject objectDetail = ((DERTaggedObject) otherNameSeq.getObjectAt(1));
									decoded = objectDetail.getObject().toASN1Primitive().toString();
									break;
								}
							}
						}
					} catch (UnsupportedEncodingException e) {
						System.out.println("Error decoding subjectAltName" + e.getLocalizedMessage());
					} catch (Exception e) {
						System.out.println("Error decoding subjectAltName" + e.getLocalizedMessage());
					}
				}
			}
		} catch (CertificateParsingException e) {
			System.out.println("Error parsing SubjectAltName in certificate: " + certificate + "\r\nerror:"
					+ e.getLocalizedMessage());
		}

		return decoded;
	}

	public static String getExtensionValue(X509Certificate certificate, String oid) throws IOException {
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

	// debug
	public static List<String> getSubjectAlternativeNames(X509Certificate certificate) {
		List<String> identities = new ArrayList<String>();
		try {
			Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
			if (altNames == null)
				return Collections.emptyList();
			for (List<?> item : altNames) {
				Integer type = (Integer) item.get(0);
				if (type == 0) {
					// Type OtherName found so return the associated value
					try {
						// Value is encoded using ASN.1 so decode it to get the
						// server's identity
						ASN1InputStream decoder = new ASN1InputStream((byte[]) item.get(1));
						Object object = decoder.readObject();
						ASN1Sequence otherNameSeq = null;
						if (object != null && object instanceof ASN1Sequence)
							otherNameSeq = (ASN1Sequence) object;
						else
							continue;
						// Check the object identifier
						ASN1ObjectIdentifier objectId = (ASN1ObjectIdentifier) otherNameSeq.getObjectAt(0);
						System.out.println("Parsing otherName for subject alternative names: " + objectId.toString());
						DERTaggedObject objectDetail = ((DERTaggedObject) otherNameSeq.getObjectAt(1));
						System.out.println("Parsing otherName for subject alternative names: "
								+ objectDetail.getObject().toASN1Primitive().toString());

						ASN1Primitive derObject = toDERObject(objectDetail.getObject().getEncoded());
						if (derObject instanceof DEROctetString) {
							DEROctetString derOctetString = (DEROctetString) derObject;
							derObject = toDERObject(derOctetString.getOctets());
							if (derObject instanceof ASN1String) {
								ASN1String s = (ASN1String) derObject;
								// decoded = s.getString();
								System.out.println(s.getString());
							}
						}

						String identity = objectId.toString();
						identities.add(identity);
					} catch (UnsupportedEncodingException e) {
						System.out.println("Error decoding subjectAltName" + e.getLocalizedMessage());
					} catch (Exception e) {
						System.out.println("Error decoding subjectAltName" + e.getLocalizedMessage());
					}
				}
				// else{
				// System.out.println("SubjectAltName of invalid type found: " +
				// certificate);
				// }
			}
		} catch (CertificateParsingException e) {
			System.out.println("Error parsing SubjectAltName in certificate: " + certificate + "\r\nerror:"
					+ e.getLocalizedMessage());
		}
		return identities;
	}
}