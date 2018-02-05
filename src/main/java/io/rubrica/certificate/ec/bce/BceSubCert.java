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

package io.rubrica.certificate.ec.bce;

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
 * Certificado intermedio del Banco Central del Ecuador, representado como un
 * objeto <code>X509Certificate</code>.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class BceSubCert extends X509Certificate {

	private X509Certificate certificate;

	public BceSubCert() {
		super();

		StringBuffer cer = new StringBuffer();
		cer.append("-----BEGIN CERTIFICATE-----\n");
		cer.append("MIII8zCCBtugAwIBAgIETj/6njANBgkqhkiG9w0BAQsFADCBwjELMAkGA1UEBhMC\n");
		cer.append("RUMxIjAgBgNVBAoTGUJBTkNPIENFTlRSQUwgREVMIEVDVUFET1IxNzA1BgNVBAsT\n");
		cer.append("LkVOVElEQUQgREUgQ0VSVElGSUNBQ0lPTiBERSBJTkZPUk1BQ0lPTi1FQ0lCQ0Ux\n");
		cer.append("DjAMBgNVBAcTBVFVSVRPMUYwRAYDVQQDEz1BVVRPUklEQUQgREUgQ0VSVElGSUNB\n");
		cer.append("Q0lPTiBSQUlaIERFTCBCQU5DTyBDRU5UUkFMIERFTCBFQ1VBRE9SMB4XDTExMDgw\n");
		cer.append("ODE1MjUyN1oXDTIxMDgwODE1NTUyN1owgaExCzAJBgNVBAYTAkVDMSIwIAYDVQQK\n");
		cer.append("ExlCQU5DTyBDRU5UUkFMIERFTCBFQ1VBRE9SMTcwNQYDVQQLEy5FTlRJREFEIERF\n");
		cer.append("IENFUlRJRklDQUNJT04gREUgSU5GT1JNQUNJT04tRUNJQkNFMQ4wDAYDVQQHEwVR\n");
		cer.append("VUlUTzElMCMGA1UEAxMcQUMgQkFOQ08gQ0VOVFJBTCBERUwgRUNVQURPUjCCAiIw\n");
		cer.append("DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK7NYNPmTUjhN0eJBvM1uWYlMgHl\n");
		cer.append("oXYBdHiYMPBVH17vVBFh4NHS7JmhnbH4NXxzb/8D9slyzBbwtXoK4y2MRBKFqwl6\n");
		cer.append("4xSCQQcXAt350qm605FBjbi+Y64wPSn69gjtIHrwJQ80rqwdsUbGlsPZFYwAaHTg\n");
		cer.append("ZsFNsYkC8oGbvpjqT0iiwEOvb+l/uou7LpWtHallQpMVonLGfRAvxXyD+JvGmaFg\n");
		cer.append("nwlOTDeGul267lQS0qTjX+22HhOX9seDX/MN/9ste6kzHnB68fWJERoXcP20Vy9K\n");
		cer.append("L+E6BQVuM3rbt0MU02/p/fgcz8n2AviWCM74G0uU6z5VBMnejIRKhEqgQ+wwKSrU\n");
		cer.append("8L1rwsfqIR2EvqAoI08zNBOYIDxpRv1WGkK9qKTlSifHqiydsmAyzcp5SCtwzD7c\n");
		cer.append("ZJ8L6hCgxwjXGwIj1UeAf7h0CVDIICF1ORODcsHJYYzbxzm7AggiLSkb97KJDpBh\n");
		cer.append("yTerIm/FPjQejpzbcAB39P82jSdIO6eihOcUPsr2SGl4eZo3MkVYGkG8gJwk7pxg\n");
		cer.append("Oc8YgCYH8W39Tp05Kq1/vMmV2+JP+AEhxKCpD7q+CgBPNTYNXTgxE/zyDJmr5pEl\n");
		cer.append("mOdLPPRZBAP+3PyRFpeItnPedLnPs3rFR2/holNn8ePzZFSj9EabRNL+JNQ8rUZW\n");
		cer.append("xjbTxxnEdSEOLWzFAgMBAAGjggMOMIIDCjB8BgNVHSAEdTBzMHEGCisGAQQBgqg7\n");
		cer.append("AQEwYzBhBggrBgEFBQcCARZVaHR0cDovL3d3dy5lY2kuYmNlLmVjL2F1dG9yaWRh\n");
		cer.append("ZC1jZXJ0aWZpY2FjaW9uL2RlY2xhcmFjaW9uLXByYWN0aWNhcy1jZXJ0aWZpY2Fj\n");
		cer.append("aW9uLnBkZjCCAhIGA1UdHwSCAgkwggIFMIICAaCCAf2gggH5pIHUMIHRMQswCQYD\n");
		cer.append("VQQGEwJFQzEiMCAGA1UEChMZQkFOQ08gQ0VOVFJBTCBERUwgRUNVQURPUjE3MDUG\n");
		cer.append("A1UECxMuRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFDSU9OLUVD\n");
		cer.append("SUJDRTEOMAwGA1UEBxMFUVVJVE8xRjBEBgNVBAMTPUFVVE9SSURBRCBERSBDRVJU\n");
		cer.append("SUZJQ0FDSU9OIFJBSVogREVMIEJBTkNPIENFTlRSQUwgREVMIEVDVUFET1IxDTAL\n");
		cer.append("BgNVBAMTBENSTDGGgfpsZGFwOi8vYmNlcWxkYXByYWl6cC5iY2UuZWMvY249Q1JM\n");
		cer.append("MSxjbj1BVVRPUklEQUQlMjBERSUyMENFUlRJRklDQUNJT04lMjBSQUlaJTIwREVM\n");
		cer.append("JTIwQkFOQ08lMjBDRU5UUkFMJTIwREVMJTIwRUNVQURPUixsPVFVSVRPLG91PUVO\n");
		cer.append("VElEQUQlMjBERSUyMENFUlRJRklDQUNJT04lMjBERSUyMElORk9STUFDSU9OLUVD\n");
		cer.append("SUJDRSxvPUJBTkNPJTIwQ0VOVFJBTCUyMERFTCUyMEVDVUFET1IsYz1FQz9hdXRo\n");
		cer.append("b3JpdHlSZXZvY2F0aW9uTGlzdD9iYXNlhiNodHRwOi8vd3d3LmVjaS5iY2UuZWMv\n");
		cer.append("Q1JML2NhY3JsLmNybDALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUqBAVqN+gmczo\n");
		cer.append("6M/ubUbv6hbSCswwHQYDVR0OBBYEFBj58PvmMhyZZjkqyouyaX1JJ7/OMAwGA1Ud\n");
		cer.append("EwQFMAMBAf8wGQYJKoZIhvZ9B0EABAwwChsEVjguMAMCAIEwDQYJKoZIhvcNAQEL\n");
		cer.append("BQADggIBAFmBSqSDfZyDSU7ucmm5++0f0mBL74FuSf5cv8IyAdRM++eqfgPL72K3\n");
		cer.append("MVMjA7uG3zH5lKo5Fa9X4GSAn8mxkOe5Y5QGdftoYXizN8l37nH3EKppzSS1dish\n");
		cer.append("VPTGUi8kjVXXDbCnLHhOlbhoulQEp0xQBUef2AoWw4YWcxJflw8Vor5oLy5eU4Jl\n");
		cer.append("s5tBI4i+q34Wjr/2RZhPOBft3EYTlD3JmznHRDwjUKH24afr1VEzECy++Fb+1ZgP\n");
		cer.append("tRTzdByWftqQdvXpxV6EUHaMHN7epgk/x99JgMxXC0ULjoxr7nsAy0jSeQeH4rd0\n");
		cer.append("kSVNIuW34Q6KkbgiASftuZWWFTZYWxInXVz4GKtpI1TOeYYhsO2bCJi0Cg2LcWhq\n");
		cer.append("jUr1ff1AzTeQRkBf9MTyHK3kOsB0Uht8nTy1z+NbfHX+jr119FCXhc3cNNAeHgHK\n");
		cer.append("UXAF+xKgjglJm9SoFske12zxVpJ+toYckn4p5Ug9w0/3pqS2qWoPy9rJrAW159aB\n");
		cer.append("r1SH+SZxZZ6Ygq9D9Br+EUfDC8ybZ5KeYjBKjtjCK7BEGywlHVBXI7Zvsq+WsLmc\n");
		cer.append("6KM75hTNJe2V2Edvnv1s3BWR7hVdtiR/C66FDD+9UtObrBDX2a3Q2efOus506le7\n");
		cer.append("Cxx6t4ioB8gMTbPDK29F4SExlbeqnVjbnSRhyQwOHGeP548aBXdu\n");
		cer.append("-----END CERTIFICATE-----");

		try {
			InputStream is = new ByteArrayInputStream(cer.toString().getBytes("UTF-8"));
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			this.certificate = (X509Certificate) cf.generateCertificate(is);
		} catch (UnsupportedEncodingException e) {
			throw new IllegalArgumentException(e);
		} catch (GeneralSecurityException e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Override
	public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
		certificate.checkValidity();
	}

	@Override
	public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
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
	public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
			NoSuchProviderException, SignatureException {
		certificate.verify(key);
	}

	@Override
	public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException,
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