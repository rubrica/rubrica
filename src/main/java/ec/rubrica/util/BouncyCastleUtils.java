/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.util;

import java.io.ByteArrayInputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Utilidades para la libreria BouncyCastle.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class BouncyCastleUtils {

	private static final Logger logger = Logger
			.getLogger(BouncyCastleUtils.class.getName());

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
			logger.fine("Read cert policies: "
					+ cert.getSerialNumber().toString());

			ByteArrayInputStream bIn = new ByteArrayInputStream(
					cert.getEncoded());
			ASN1InputStream aIn = new ASN1InputStream(bIn);
			ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
			X509CertificateStructure obj = new X509CertificateStructure(seq);
			TBSCertificateStructure tbsCert = obj.getTBSCertificate();
			if (tbsCert.getVersion() == 3) {
				X509Extensions ext = tbsCert.getExtensions();
				if (ext != null) {
					Enumeration en = ext.oids();
					while (en.hasMoreElements()) {
						DERObjectIdentifier oid = (DERObjectIdentifier) en
								.nextElement();
						X509Extension extVal = ext.getExtension(oid);
						ASN1OctetString oct = extVal.getValue();
						ASN1InputStream extIn = new ASN1InputStream(
								new ByteArrayInputStream(oct.getOctets()));

						if (oid.equals(X509Extension.certificatePolicies)) {
							ASN1Sequence cp = (ASN1Sequence) extIn.readObject();
							for (int i = 0; i != cp.size(); i++) {
								PolicyInformation pol = PolicyInformation
										.getInstance(cp.getObjectAt(i));
								DERObjectIdentifier dOid = pol
										.getPolicyIdentifier();
								String soid2 = dOid.getId();

								logger.fine("Policy: " + soid2);
								if (soid2.startsWith(sOid))
									return true;
							}
						}
					}
				}

			}
		} catch (Exception ex) {
			logger.severe("Error reading cert policies: " + ex);
		}
		return false;
	}
}