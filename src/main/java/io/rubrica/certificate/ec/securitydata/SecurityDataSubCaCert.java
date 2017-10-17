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
 * Certificado intermedio del Security Data, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class SecurityDataSubCaCert extends X509Certificate {

	private X509Certificate certificate;

	public SecurityDataSubCaCert() {
		super();

		StringBuffer cer = new StringBuffer();
		cer.append("-----BEGIN CERTIFICATE-----\n");
		cer.append("MIIFpDCCBIygAwIBAgIETVxNgTANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC\n");
		cer.append("RUMxGzAZBgNVBAoTElNFQ1VSSVRZIERBVEEgUy5BLjEwMC4GA1UECxMnRU5USURB\n");
		cer.append("RCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFDSU9OMTYwNAYDVQQDEy1BVVRP\n");
		cer.append("UklEQUQgREUgQ0VSVElGSUNBQ0lPTiBSQUlaIFNFQ1VSSVRZIERBVEEwHhcNMTEw\n");
		cer.append("MjE2MjI1NTQwWhcNMjYwMjE2MjMyNTQwWjCBkzELMAkGA1UEBhMCRUMxGzAZBgNV\n");
		cer.append("BAoTElNFQ1VSSVRZIERBVEEgUy5BLjEwMC4GA1UECxMnRU5USURBRCBERSBDRVJU\n");
		cer.append("SUZJQ0FDSU9OIERFIElORk9STUFDSU9OMTUwMwYDVQQDEyxBVVRPUklEQUQgREUg\n");
		cer.append("Q0VSVElGSUNBQ0lPTiBTVUIgU0VDVVJJVFkgREFUQTCCASIwDQYJKoZIhvcNAQEB\n");
		cer.append("BQADggEPADCCAQoCggEBAImswItj4Vatw0D4MR30gRBLmZFywEHYyoSsJ03sZq80\n");
		cer.append("AbmjfyQ9uG5h6LKJM5CJMC7Y1601Agyb3phkmr/ULFhLdry8j+uXb0amI7mIAK1Z\n");
		cer.append("d1mLMauJIxY4cwgH8U3YJgEvh+DL/vv5NSOfWHJGefM1Rg5146pm5BHX+dnzz6HE\n");
		cer.append("fcLcnIEaQp2sK8j1xzJxaymxGgpXFQMSmxXYD6j2Xzy7uLGRCvPMvJ/GvrQ0F+N6\n");
		cer.append("5Z1iN0uKn+uOfYGlJ0iDhKRMtb82D1T9IGZM6nWwlLkc6lMd+X0gRNCTJBCvxyCc\n");
		cer.append("v8C2oMPndSIOGrYGh9MV/lUmTmKC3bhxraxM0OaEyXsCAwEAAaOCAfswggH3MIIB\n");
		cer.append("mAYDVR0fBIIBjzCCAYswggGHoIIBg6CCAX+GgdNsZGFwOi8vU0lTTERBUC5TRUNV\n");
		cer.append("UklUWURBVEEuTkVULkVDL2NuPUNSTDEsY249QVVUT1JJREFEJTIwREUlMjBDRVJU\n");
		cer.append("SUZJQ0FDSU9OJTIwUkFJWiUyMFNFQ1VSSVRZJTIwREFUQSxvdT1FTlRJREFEJTIw\n");
		cer.append("REUlMjBDRVJUSUZJQ0FDSU9OJTIwREUlMjBJTkZPUk1BQ0lPTixvPVNFQ1VSSVRZ\n");
		cer.append("JTIwREFUQSUyMFMuQS4sYz1FQz9hdXRob3JpdHlSZXZvY2F0aW9uTGlzdD9iYXNl\n");
		cer.append("pIGmMIGjMQswCQYDVQQGEwJFQzEbMBkGA1UEChMSU0VDVVJJVFkgREFUQSBTLkEu\n");
		cer.append("MTAwLgYDVQQLEydFTlRJREFEIERFIENFUlRJRklDQUNJT04gREUgSU5GT1JNQUNJ\n");
		cer.append("T04xNjA0BgNVBAMTLUFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVogU0VD\n");
		cer.append("VVJJVFkgREFUQTENMAsGA1UEAxMEQ1JMMTALBgNVHQ8EBAMCAQYwHwYDVR0jBBgw\n");
		cer.append("FoAUlgOI1huMRCFc4mButfelH3Whbe4wHQYDVR0OBBYEFPcvTOB152KjeJZbBrYu\n");
		cer.append("cTvMbD+QMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADMBZO0+fUjX\n");
		cer.append("yXvVaaLtKqlPf3jQLRAp6ZAEyd4EgjV7zz8wm3giaLqZGw8pgEDDOc9KaZJQ+qDC\n");
		cer.append("So+JUnDggqMNZ478wMeP9WzSgQm5za9+lWjn2Ff/cBp6kWqVuevd+y4BsoDyvi2G\n");
		cer.append("7ulTxzulP/0U4ipkgf2uHrgnM7hnKnzMTmnZPKV8KuC7AHI45TZ7yJkpmh30jjkR\n");
		cer.append("BXNFjViZ6yGnt/wYpfeaOqGJFHpijgVUFMxic6J8XGuDcM5Y42ii1PtdwcmGOBRf\n");
		cer.append("HpZATprN6Ntux10aEEfPD4jM8CJYq31x3QWYglLozezl/fiJ6RKGZ1ZP1I4BJU7x\n");
		cer.append("mPCvgJqeNeI=\n");
		cer.append("-----END CERTIFICATE-----");

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