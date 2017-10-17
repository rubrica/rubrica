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

package io.rubrica.certificate.ec.securitydata;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

/**
 * Certificado raiz de Security Data, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class SecurityDataCaCert extends X509Certificate {

	private X509Certificate certificate;

	public SecurityDataCaCert() {
		super();

		StringBuffer cer = new StringBuffer();
		cer.append("-----BEGIN CERTIFICATE-----\n");
		cer.append("MIIENDCCAxygAwIBAgIETVxNRjANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC\n");
		cer.append("RUMxGzAZBgNVBAoTElNFQ1VSSVRZIERBVEEgUy5BLjEwMC4GA1UECxMnRU5USURB\n");
		cer.append("RCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFDSU9OMTYwNAYDVQQDEy1BVVRP\n");
		cer.append("UklEQUQgREUgQ0VSVElGSUNBQ0lPTiBSQUlaIFNFQ1VSSVRZIERBVEEwHhcNMTEw\n");
		cer.append("MjE2MjE0ODUwWhcNMzEwMjE2MjIxODUwWjCBlDELMAkGA1UEBhMCRUMxGzAZBgNV\n");
		cer.append("BAoTElNFQ1VSSVRZIERBVEEgUy5BLjEwMC4GA1UECxMnRU5USURBRCBERSBDRVJU\n");
		cer.append("SUZJQ0FDSU9OIERFIElORk9STUFDSU9OMTYwNAYDVQQDEy1BVVRPUklEQUQgREUg\n");
		cer.append("Q0VSVElGSUNBQ0lPTiBSQUlaIFNFQ1VSSVRZIERBVEEwggEiMA0GCSqGSIb3DQEB\n");
		cer.append("AQUAA4IBDwAwggEKAoIBAQCxmlv/O072egF5HYTJJkGutwPkXL5bB0oA+PoaDgcm\n");
		cer.append("+zbfZ9c0dFumdzqlpfIC+wBsfp03iXYpP/WImeBj7vrNypwdjtCr1sXiydcxeZ1a\n");
		cer.append("OR3o6kKDCA1lrlFyrlGpDiNKp+uOudAN1EHhv/qlP7dGEDdqR4cIxa1sQau9TETH\n");
		cer.append("sZ8QXlw7mvy8EPoFx6iRWoYYKzbFllqPAKpXqZRLxB1LU8XQrYR/Qcna0dKipW9E\n");
		cer.append("fppzKcGAmRnnwh54wwBjs4hjJxaU+pAoZfrAwkb2YuHrsqjKKXsE2SNErIsxGHcY\n");
		cer.append("QAZK2bQ8V2VhyIxHtLPkIStub87+A3z+1YDpo6EFRsopAgMBAAGjgYswgYgwKwYD\n");
		cer.append("VR0QBCQwIoAPMjAxMTAyMTYyMTQ4NTBagQ8yMDMxMDIxNjIyMTg1MFowCwYDVR0P\n");
		cer.append("BAQDAgEGMB8GA1UdIwQYMBaAFJYDiNYbjEQhXOJgbrX3pR91oW3uMB0GA1UdDgQW\n");
		cer.append("BBSWA4jWG4xEIVziYG6196UfdaFt7jAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB\n");
		cer.append("CwUAA4IBAQBKia5BQFNkgji0MqpQnVOEnhJulge5/pbk0BGhGB3kuRozThu72BhV\n");
		cer.append("WmTJG2n2soUGReob/eEDbv2Dd6HAPlotjmZhLa1gTvAMlZjOFIp5ZSBp4i0CxUgn\n");
		cer.append("MYhIkny9EwIzoL3uHTPTaC7z+m0eU4lmErOFdsPxYP28az9kJTTf9C98HaWnaTU2\n");
		cer.append("UC4P16k5egDSQkh5yb0qVH7LQsHowVPJteTa+lgz8ze3UoAyxZldmVQYlRXBA2Gb\n");
		cer.append("CA2PUk/fmdNPN76fI473m7NCXIGP1718N1/+fOVPjCAUwMyArIvmwM+IeP5vLvPt\n");
		cer.append("/4BhckuhKgpJE8T88mqWfbQKuz6iU0FW\n");
		cer.append("-----END CERTIFICATE-----\n");

		try {
			InputStream is = new ByteArrayInputStream(cer.toString().getBytes(
					"UTF-8"));
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			this.certificate = (X509Certificate) cf.generateCertificate(is);
		} catch (UnsupportedEncodingException e) {
			throw new IllegalArgumentException(e);
		} catch (GeneralSecurityException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public void checkValidity() throws CertificateExpiredException,
			CertificateNotYetValidException {
		certificate.checkValidity();
	}

	@Override
	public void checkValidity(Date date) throws CertificateExpiredException,
			CertificateNotYetValidException {
		certificate.checkValidity(date);
	}

	@Override
	public int getBasicConstraints() {
		return certificate.getBasicConstraints();
	}

	@Override
	public Principal getIssuerDN() {
		return certificate.getIssuerDN();
	}

	@Override
	public boolean[] getIssuerUniqueID() {
		return certificate.getIssuerUniqueID();
	}

	@Override
	public boolean[] getKeyUsage() {
		return certificate.getKeyUsage();
	}

	@Override
	public Date getNotAfter() {
		return certificate.getNotAfter();
	}

	@Override
	public Date getNotBefore() {
		return certificate.getNotBefore();
	}

	@Override
	public BigInteger getSerialNumber() {
		return certificate.getSerialNumber();
	}

	@Override
	public String getSigAlgName() {
		return certificate.getSigAlgName();
	}

	@Override
	public String getSigAlgOID() {
		return certificate.getSigAlgOID();
	}

	@Override
	public byte[] getSigAlgParams() {
		return certificate.getSigAlgParams();
	}

	@Override
	public byte[] getSignature() {
		return certificate.getSignature();
	}

	@Override
	public Principal getSubjectDN() {
		return certificate.getSubjectDN();
	}

	@Override
	public boolean[] getSubjectUniqueID() {
		return certificate.getSubjectUniqueID();
	}

	@Override
	public byte[] getTBSCertificate() throws CertificateEncodingException {
		return certificate.getTBSCertificate();
	}

	@Override
	public int getVersion() {
		return certificate.getVersion();
	}

	@Override
	public byte[] getEncoded() throws CertificateEncodingException {
		return certificate.getEncoded();
	}

	@Override
	public PublicKey getPublicKey() {
		return certificate.getPublicKey();
	}

	@Override
	public String toString() {
		return certificate.toString();
	}

	@Override
	public void verify(PublicKey key) throws CertificateException,
			NoSuchAlgorithmException, InvalidKeyException,
			NoSuchProviderException, SignatureException {
		certificate.verify(key);
	}

	@Override
	public void verify(PublicKey key, String sigProvider)
			throws CertificateException, NoSuchAlgorithmException,
			InvalidKeyException, NoSuchProviderException, SignatureException {
		certificate.verify(key, sigProvider);
	}

	public Set<String> getCriticalExtensionOIDs() {
		return certificate.getCriticalExtensionOIDs();
	}

	public byte[] getExtensionValue(String oid) {
		return certificate.getExtensionValue(oid);
	}

	public Set<String> getNonCriticalExtensionOIDs() {
		return certificate.getNonCriticalExtensionOIDs();
	}

	public boolean hasUnsupportedCriticalExtension() {
		return certificate.hasUnsupportedCriticalExtension();
	}
}