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
 * Certificado raiz del Banco Central del Ecuador, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class BceCaCert extends X509Certificate {

	private X509Certificate certificate;

	public BceCaCert() {
		super();

		StringBuffer cer = new StringBuffer();
		cer.append("-----BEGIN CERTIFICATE-----\n");
		cer.append("MIIJMzCCBxugAwIBAgIETj/6bTANBgkqhkiG9w0BAQsFADCBwjELMAkGA1UEBhMC\n");
		cer.append("RUMxIjAgBgNVBAoTGUJBTkNPIENFTlRSQUwgREVMIEVDVUFET1IxNzA1BgNVBAsT\n");
		cer.append("LkVOVElEQUQgREUgQ0VSVElGSUNBQ0lPTiBERSBJTkZPUk1BQ0lPTi1FQ0lCQ0Ux\n");
		cer.append("DjAMBgNVBAcTBVFVSVRPMUYwRAYDVQQDEz1BVVRPUklEQUQgREUgQ0VSVElGSUNB\n");
		cer.append("Q0lPTiBSQUlaIERFTCBCQU5DTyBDRU5UUkFMIERFTCBFQ1VBRE9SMB4XDTExMDgw\n");
		cer.append("ODE0MzIwNVoXDTMxMDgwODE1MDIwNVowgcIxCzAJBgNVBAYTAkVDMSIwIAYDVQQK\n");
		cer.append("ExlCQU5DTyBDRU5UUkFMIERFTCBFQ1VBRE9SMTcwNQYDVQQLEy5FTlRJREFEIERF\n");
		cer.append("IENFUlRJRklDQUNJT04gREUgSU5GT1JNQUNJT04tRUNJQkNFMQ4wDAYDVQQHEwVR\n");
		cer.append("VUlUTzFGMEQGA1UEAxM9QVVUT1JJREFEIERFIENFUlRJRklDQUNJT04gUkFJWiBE\n");
		cer.append("RUwgQkFOQ08gQ0VOVFJBTCBERUwgRUNVQURPUjCCAiIwDQYJKoZIhvcNAQEBBQAD\n");
		cer.append("ggIPADCCAgoCggIBALw9wH7DgFMR3kHUp72Wpug1N8JWFRthnhqxMWxOXVnGoYbG\n");
		cer.append("sdVTaycXSeVnWt03AZDGw8x7FNh3A2Hh9vtOZGnFCOWJZyDqF5KiGHN6Jiy1mAD4\n");
		cer.append("qAgFghWCh78OBO19ThI3PAflevMwqnWF5DJsqBdV8lqvOh8L5DX54PDYcs2zXlBI\n");
		cer.append("76hz/Ye4BXI1dMSmlKbAVaiBMMG+Ye/szAL4RQCZNpyi65nbgXKztbvWjwJiJIbW\n");
		cer.append("KND9Cu40+wZ6tm+OcTKyNQfhvdSfqRZ7tQv2LDwhPotuztyS6RljyMyNe1l3A6hW\n");
		cer.append("D/JnS65gHi46H0WjrRqtH5ObqhTEwZszOPdU32VFcLhUtZhPQp0M74Wa2dXy9d+s\n");
		cer.append("DBCdI9GZcaY+nzaNMbPEdT5lFg1Uc6ksWbWvj5udZMBhygZj1PtaWFjmqpZcdd9v\n");
		cer.append("Z29GGbOtKB6bx162YGaK5sGjB385WVDRAi6Uzjl+0CpoDJjP7YS9tZrXlDs4gepp\n");
		cer.append("KETthU2cpk73jYflzBeFFavuxNHGk6cVNgFrrhht0X0/eMhgq0Go4NUyY11g/r7f\n");
		cer.append("3Upf0YR7OxOacjDbLpIbNxzeH2htcD0zpyS485TWnBnarjBhgO1ywQmRQ/Ryl8Zq\n");
		cer.append("u7eWKBOfk++hibqJNfeLwEY3uBGoITbTXpBiX2u6U86bRGHES0Cm6mud5xErAgMB\n");
		cer.append("AAGjggMtMIIDKTB8BgNVHSAEdTBzMHEGCisGAQQBgqg7AQEwYzBhBggrBgEFBQcC\n");
		cer.append("ARZVaHR0cDovL3d3dy5lY2kuYmNlLmVjL2F1dG9yaWRhZC1jZXJ0aWZpY2FjaW9u\n");
		cer.append("L2RlY2xhcmFjaW9uLXByYWN0aWNhcy1jZXJ0aWZpY2FjaW9uLnBkZjARBglghkgB\n");
		cer.append("hvhCAQEEBAMCAAcwggHtBgNVHR8EggHkMIIB4DCCAdygggHYoIIB1KSB1DCB0TEL\n");
		cer.append("MAkGA1UEBhMCRUMxIjAgBgNVBAoTGUJBTkNPIENFTlRSQUwgREVMIEVDVUFET1Ix\n");
		cer.append("NzA1BgNVBAsTLkVOVElEQUQgREUgQ0VSVElGSUNBQ0lPTiBERSBJTkZPUk1BQ0lP\n");
		cer.append("Ti1FQ0lCQ0UxDjAMBgNVBAcTBVFVSVRPMUYwRAYDVQQDEz1BVVRPUklEQUQgREUg\n");
		cer.append("Q0VSVElGSUNBQ0lPTiBSQUlaIERFTCBCQU5DTyBDRU5UUkFMIERFTCBFQ1VBRE9S\n");
		cer.append("MQ0wCwYDVQQDEwRDUkwxhoH6bGRhcDovL2JjZXFsZGFwcmFpenAuYmNlLmVjL2Nu\n");
		cer.append("PUNSTDEsY249QVVUT1JJREFEJTIwREUlMjBDRVJUSUZJQ0FDSU9OJTIwUkFJWiUy\n");
		cer.append("MERFTCUyMEJBTkNPJTIwQ0VOVFJBTCUyMERFTCUyMEVDVUFET1IsbD1RVUlUTyxv\n");
		cer.append("dT1FTlRJREFEJTIwREUlMjBDRVJUSUZJQ0FDSU9OJTIwREUlMjBJTkZPUk1BQ0lP\n");
		cer.append("Ti1FQ0lCQ0Usbz1CQU5DTyUyMENFTlRSQUwlMjBERUwlMjBFQ1VBRE9SLGM9RUM/\n");
		cer.append("YXV0aG9yaXR5UmV2b2NhdGlvbkxpc3Q/YmFzZTArBgNVHRAEJDAigA8yMDExMDgw\n");
		cer.append("ODE0MzIwNVqBDzIwMzEwODA4MTUwMjA1WjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgw\n");
		cer.append("FoAUqBAVqN+gmczo6M/ubUbv6hbSCswwHQYDVR0OBBYEFKgQFajfoJnM6OjP7m1G\n");
		cer.append("7+oW0grMMAwGA1UdEwQFMAMBAf8wHQYJKoZIhvZ9B0EABBAwDhsIVjguMDo0LjAD\n");
		cer.append("AgSQMA0GCSqGSIb3DQEBCwUAA4ICAQCt5F5DaFGcZqrQ5uKKrk2D1KD2DlNbniaK\n");
		cer.append("IwJfZ36tLYUuyu7VmLZZdrVKqjC+FYAZIQJn/q2w/0JN5I5YK+Yj1UEa9nlmshRH\n");
		cer.append("aCEJXZokLXFjD4ZayiZgJh7OcMEV7G9VFFP2WF4iDflSG0drhn152Fllh+y1ZHov\n");
		cer.append("hX6TlCT0y5iAq+zzq2Utu6Gs1SU5U7fCC7gNYOeztPehqlnSTaD1xAbqnTVOBS1Z\n");
		cer.append("hoCQio5vF98TS36ItfjDA0bO12FiJKOLx9WNiimDxy0KIFSfifD1FfmUO5MYgcke\n");
		cer.append("CTLnkGHtCadhpEsy6HwHeeuLNPkp5DMGJeBX1XAjVC50ulw36lXuryJ9/FRBpbdg\n");
		cer.append("uLJIssFndQlr6klA5LdK44yFVr3+1d+59fNuiFQnKQV7bFQfApv5FqvqyfNEEI1K\n");
		cer.append("1prM82aq24xDT5OwsyRnf+F7p6OwQTYmGYkrGH5RlqFI+XC8ckMip3XecFb6Qyur\n");
		cer.append("kaA/286eYUOZiJpPgn/qlisNreF0GTLi9tBzExGCD+BdsYGqMu/gx8lgMbF3b+HK\n");
		cer.append("eQe8+kExkb7LVYhbTlOBZzB0da/cDmvg1V+pgrXu0qUX/YnQyybnA9nyQdLj60/3\n");
		cer.append("sUlWyxURbu33kTNnrPJmcHjRa561Co84NYKifLrDSgAChLQry/eItvhzFYu33Td9\n");
		cer.append("TkHa++TQjg==\n");
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