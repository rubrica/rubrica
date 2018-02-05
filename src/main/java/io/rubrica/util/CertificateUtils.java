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
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 * Utilidades para trabajar con certificados.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class CertificateUtils {

	private static final Logger logger = Logger.getLogger(CertificateUtils.class.getName());

	/**
	 * Return an X509Certificate from a certificate encoded in byte[]
	 */
	public static X509Certificate certificateFromByteArray(byte[] bytes) {
		try {
			return (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(new ByteArrayInputStream(bytes));
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * Return the crlDistributionPoints extension from a certificate
	 */
	public static List<String> getCrlDistributionPoints(X509Certificate cert) throws IOException {
		byte[] crldpExt = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
		ASN1Primitive object = X509ExtensionUtil.fromExtensionValue(crldpExt);
		CRLDistPoint distPoint = CRLDistPoint.getInstance(object);
		List<String> crlUrls = new ArrayList<>();

		for (DistributionPoint dp : distPoint.getDistributionPoints()) {
			DistributionPointName dpn = dp.getDistributionPoint();
			if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
				GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
				for (GeneralName genName : genNames) {
					if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
						crlUrls.add(DERIA5String.getInstance(genName.getName()).getString());
					}
				}
			}
		}

		return crlUrls;
	}

	/**
	 * Return the OCSP Responder address contained in the certificate More precisely
	 * the it is contained in the authorityInfoAccess extension
	 */
	public static List<String> getAuthorityInformationAccess(X509Certificate cert) throws IOException {
		byte[] authInfoExt = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
		ASN1Sequence object = (ASN1Sequence) X509ExtensionUtil.fromExtensionValue(authInfoExt);
		AuthorityInformationAccess authInfo = AuthorityInformationAccess.getInstance(object);
		List<String> ocspUrls = new ArrayList<>();

		for (AccessDescription accessDescription : authInfo.getAccessDescriptions()) {
			GeneralName genName = accessDescription.getAccessLocation();

			if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
				DERIA5String str = DERIA5String.getInstance(genName.getName());
				String accessLocation = str.getString();
				ocspUrls.add(accessLocation);
			}
		}

		return ocspUrls;
	}

	/**
	 * Obtiene el nombre com&uacute;n (Common Name, CN) del titular de un
	 * certificado X.509. Si no se encuentra el CN, se devuelve la unidad
	 * organizativa (Organization Unit, OU).
	 * 
	 * @param c
	 *            Certificado X.509 del cual queremos obtener el nombre com&uacute;n
	 * @return Nombre com&uacute;n (Common Name, CN) del titular de un certificado
	 *         X.509
	 */
	public static String getCN(X509Certificate c) {
		if (c == null) {
			return null;
		}
		return getCN(c.getSubjectX500Principal().toString());
	}

	/**
	 * Obtiene el nombre común (Common Name, CN) de un <i>Principal</i> X.400. Si no
	 * se encuentra el CN, se devuelve la unidad organizativa (Organization Unit,
	 * OU).
	 * 
	 * @param principal
	 *            <i>Principal</i> del cual queremos obtener el nombre común
	 * @return Nombre común (Common Name, CN) de un <i>Principal</i> X.400
	 */
	public static String getCN(String principal) {
		if (principal == null) {
			return null;
		}

		String rdn = getRDNvalueFromLdapName("cn", principal);
		if (rdn == null) {
			rdn = getRDNvalueFromLdapName("ou", principal);
		}

		if (rdn != null) {
			return rdn;
		}

		final int i = principal.indexOf('=');
		if (i != -1) {
			logger.warning(
					"No se ha podido obtener el Common Name ni la Organizational Unit, se devolvera el fragmento mas significativo");
			return getRDNvalueFromLdapName(principal.substring(0, i), principal);
		}

		logger.warning("Principal no valido, se devolvera la entrada");
		return principal;
	}

	/**
	 * Recupera el valor de un RDN (<i>Relative Distinguished Name</i>) de un
	 * principal. El valor de retorno no incluye el nombre del RDN, el igual, ni las
	 * posibles comillas que envuelvan el valor. La función no es sensible a la
	 * capitalización del RDN. Si no se encuentra, se devuelve {@code null}.
	 * 
	 * @param rdn
	 *            RDN que deseamos encontrar.
	 * @param principal
	 *            Principal del que extraer el RDN (seg&uacute;n la
	 *            <a href="http://www.ietf.org/rfc/rfc4514.txt">RFC 4514</a>).
	 * @return Valor del RDN indicado o {@code null} si no se encuentra.
	 */
	public static String getRDNvalueFromLdapName(String rdn, String principal) {

		int offset1 = 0;
		while ((offset1 = principal.toLowerCase(Locale.US).indexOf(rdn.toLowerCase(), offset1)) != -1) {

			if (offset1 > 0 && principal.charAt(offset1 - 1) != ',' && principal.charAt(offset1 - 1) != ' ') {
				offset1++;
				continue;
			}

			offset1 += rdn.length();
			while (offset1 < principal.length() && principal.charAt(offset1) == ' ') {
				offset1++;
			}

			if (offset1 >= principal.length()) {
				return null;
			}

			if (principal.charAt(offset1) != '=') {
				continue;
			}

			offset1++;
			while (offset1 < principal.length() && principal.charAt(offset1) == ' ') {
				offset1++;
			}

			if (offset1 >= principal.length()) {
				return "";
			}

			int offset2;
			if (principal.charAt(offset1) == ',') {
				return "";
			} else if (principal.charAt(offset1) == '"') {
				offset1++;
				if (offset1 >= principal.length()) {
					return "";
				}

				offset2 = principal.indexOf('"', offset1);
				if (offset2 == offset1) {
					return "";
				} else if (offset2 != -1) {
					return principal.substring(offset1, offset2);
				} else {
					return principal.substring(offset1);
				}
			} else {
				offset2 = principal.indexOf(',', offset1);
				if (offset2 != -1) {
					return principal.substring(offset1, offset2).trim();
				}
				return principal.substring(offset1).trim();
			}
		}

		return null;
	}
}