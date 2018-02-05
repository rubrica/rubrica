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

package io.rubrica.util;

import java.io.ByteArrayInputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Utilidades para la libreria BouncyCastle.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class BouncyCastleUtils {

	private static final Logger logger = Logger.getLogger(BouncyCastleUtils.class.getName());

	/**
	 * Inicializa el Proveedor de Seguridad BouncyCastle
	 */
	public static void initializeBouncyCastle() {
		AccessController.doPrivileged(new PrivilegedAction<Void>() {
			public Void run() {
				Security.addProvider(new BouncyCastleProvider());
				return null;
			}
		});
	}

	public static boolean certificateHasPolicy(X509Certificate cert, String sOid) {
		try {
			ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
			ASN1InputStream aIn = new ASN1InputStream(bIn);
			ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
			Certificate obj = Certificate.getInstance(seq);
			TBSCertificate tbsCert = obj.getTBSCertificate();

			if (tbsCert.getVersionNumber() == 3) {
				Extensions ext = tbsCert.getExtensions();

				if (ext != null) {
					Enumeration en = ext.oids();
					while (en.hasMoreElements()) {
						ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) en.nextElement();
						Extension extVal = ext.getExtension(oid);
						ASN1OctetString oct = extVal.getExtnValue();
						ASN1InputStream extIn = new ASN1InputStream(new ByteArrayInputStream(oct.getOctets()));

						if (oid.equals(Extension.certificatePolicies)) {
							ASN1Sequence cp = (ASN1Sequence) extIn.readObject();
							for (int i = 0; i != cp.size(); i++) {
								PolicyInformation pol = PolicyInformation.getInstance(cp.getObjectAt(i));
								ASN1ObjectIdentifier dOid = pol.getPolicyIdentifier();
								String soid2 = dOid.getId();

								if (soid2.startsWith(sOid)) {
									extIn.close();
									return true;
								}
							}
						}
						extIn.close();
					}
				}
			}
		} catch (Exception ex) {
			logger.severe("Error reading cert policies: " + ex);
		}

		return false;
	}
}