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
 * Certificado intermedio para pruebas del Banco Central del Ecuador,
 * representado como un objeto <code>X509Certificate</code>.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class BceSubTestCert extends X509Certificate {

	private X509Certificate certificate;

	public BceSubTestCert() {
		super();

		StringBuffer cer = new StringBuffer();
		cer.append("-----BEGIN CERTIFICATE-----\n");
		cer.append("MIII/TCCBuWgAwIBAgIETdwJTTANBgkqhkiG9w0BAQsFADCBzTELMAkGA1UEBhMC\n");
		cer.append("RUMxJzAlBgNVBAoTHkJBTkNPIENFTlRSQUwgREVMIEVDVUFET1IgVEVTVDE8MDoG\n");
		cer.append("A1UECxMzRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFDSU9OLUVD\n");
		cer.append("SUJDRSBURVNUMQ4wDAYDVQQHEwVRVUlUTzFHMEUGA1UEAxM+QVVUT1JJREFEIERF\n");
		cer.append("IENFUlRJRklDQUNJT04gUkFJWiBCQU5DTyBDRU5UUkFMIERFTCBFQ1VBRE9SIFRF\n");
		cer.append("U1QwHhcNMTEwNjA2MTUyNzE4WhcNMjEwNjA2MTU1NzE4WjCBsDELMAkGA1UEBhMC\n");
		cer.append("RUMxJzAlBgNVBAoTHkJBTkNPIENFTlRSQUwgREVMIEVDVUFET1IgVEVTVDE8MDoG\n");
		cer.append("A1UECxMzRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFDSU9OLUVD\n");
		cer.append("SUJDRSBURVNUMQ4wDAYDVQQHEwVRVUlUTzEqMCgGA1UEAxMhQUMgQkFOQ08gQ0VO\n");
		cer.append("VFJBTCBERUwgRUNVQURPUiBURVNUMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\n");
		cer.append("CgKCAgEAwK7YYlyWhO84Z8ceTL9xK1jojFvjDVSBc4h19ApMtNqhoApIb+EfhHSH\n");
		cer.append("3T1fiNHOkaGfO/X5jBcjvHd+Ui3V2hVh5lgrU2cxo9KipGB747rOvUTtNSpk2v94\n");
		cer.append("EHQVGnhFyrqLlOgKS5AqPjaIB3EvfzZLe+tA5IJ627OOaZxeDz0Z/4lKnF3sTqrl\n");
		cer.append("jMkZ0/pRvwqwRe8QkjSEvh3aQwMw08nlz5eXhwRlgLUDxy5qu+0/1oyUTaCLbvS4\n");
		cer.append("iyUWUO6LGGBthsXt7HiblsFmGb4OtKzTDffXtMw1UVCCc5MIYK6D/LvD5Y7U1L2H\n");
		cer.append("ZGh+mWNvRgvOoYbhkSvYAaJMQ48h3abkH+yI/H98BdoJd1bf609WbsOcsmbAO8D9\n");
		cer.append("Jhf6HGE9jMo1XzreDVC3Yn5NSBQY6nmQlQm/UqjTBvzkGZTxgvUC3vgbXN8Qzx51\n");
		cer.append("5FFzDS+53i9ZPm4KGJ3ipLi9sModR6BuMV4MBHPDN+NnzhLmg13cpIgJgklsDofn\n");
		cer.append("9cQctjbCr3IoUArDxpu3d5RK64/0azQlqLie962CUq59k99BSz4/HZaR8/vctks+\n");
		cer.append("I6b9h0+lrT8kdppW0Ehuw/Mq82X0fb8Gi7L1mArn3+0WJaS0PWpwtfp0MwaC5Bp4\n");
		cer.append("RsI7pFHacpJt7VUIk+mpkve/hBM9ayCiJ/YXQkF7xvlL3GhKQaUCAwEAAaOCAv4w\n");
		cer.append("ggL6MHYGA1UdIARvMG0wawYKKwYBBAGCqDsBATBdMFsGCCsGAQUFBwIBFk9odHRw\n");
		cer.append("Oi8vd3d3LmVjaS5iY2UuZWMvaW50ZXJtZWRpYS9lY2liY2UvZGVjbGFyYWNpb24t\n");
		cer.append("cHJhY3RpY2FzLWNlcnRpZmljYWNpb24ucGRmMIICCAYDVR0fBIIB/zCCAfswggH3\n");
		cer.append("oIIB86CCAe+kgd8wgdwxCzAJBgNVBAYTAkVDMScwJQYDVQQKEx5CQU5DTyBDRU5U\n");
		cer.append("UkFMIERFTCBFQ1VBRE9SIFRFU1QxPDA6BgNVBAsTM0VOVElEQUQgREUgQ0VSVElG\n");
		cer.append("SUNBQ0lPTiBERSBJTkZPUk1BQ0lPTi1FQ0lCQ0UgVEVTVDEOMAwGA1UEBxMFUVVJ\n");
		cer.append("VE8xRzBFBgNVBAMTPkFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVogQkFO\n");
		cer.append("Q08gQ0VOVFJBTCBERUwgRUNVQURPUiBURVNUMQ0wCwYDVQQDEwRDUkwxhoIBCWxk\n");
		cer.append("YXA6Ly9iY2VxbGRhcHJhaXp0LmJjZS5lYy9jbj1DUkwxLGNuPUFVVE9SSURBRCUy\n");
		cer.append("MERFJTIwQ0VSVElGSUNBQ0lPTiUyMFJBSVolMjBCQU5DTyUyMENFTlRSQUwlMjBE\n");
		cer.append("RUwlMjBFQ1VBRE9SJTIwVEVTVCxsPVFVSVRPLG91PUVOVElEQUQlMjBERSUyMENF\n");
		cer.append("UlRJRklDQUNJT04lMjBERSUyMElORk9STUFDSU9OLUVDSUJDRSUyMFRFU1Qsbz1C\n");
		cer.append("QU5DTyUyMENFTlRSQUwlMjBERUwlMjBFQ1VBRE9SJTIwVEVTVCxjPUVDP2F1dGhv\n");
		cer.append("cml0eVJldm9jYXRpb25MaXN0P2Jhc2UwCwYDVR0PBAQDAgEGMB8GA1UdIwQYMBaA\n");
		cer.append("FP2Nek1J7bRjIw5c67uS9Gpsgyr0MB0GA1UdDgQWBBS2dEdW/LX9oye1e5jX/oIU\n");
		cer.append("x6uVmDAMBgNVHRMEBTADAQH/MBkGCSqGSIb2fQdBAAQMMAobBFY4LjADAgCBMA0G\n");
		cer.append("CSqGSIb3DQEBCwUAA4ICAQBC2bb9iSH0+RiFZD3rdFmsGyoATOcAEviEs2RXrolm\n");
		cer.append("Kx87cKV0dEC4rlW3mz286PXXfQ2/IyNU3iyonGchkjc+XbEfBoB5A6smRzhBbJ/0\n");
		cer.append("30de4xWtqMhSfdVDQkOvRoMSchgTUJvmJv1bISnqnSZcYaGxO/oRDUYbNl53fV1u\n");
		cer.append("K8kbR9oo/3gGoc2xHqDM6kHjrolGk673mIREZ4djzSUsGBI/twiqJYpzbCT/+mYS\n");
		cer.append("mhKxBhiv2dQwxl0fZcLyVjJSx4Qop9RrOWEQj+lNwmqdkrs/oFPu6RrwcfLnB9Pu\n");
		cer.append("JYvArehpgO5VBEdvlLeYuJhu5z4X2ZTsuOxiWby/Leyrt/IrpMigoE749Moq3k8g\n");
		cer.append("yLF6F0OVeuwODsgY30I7ovj6jiXqiKXDr32GLGBtDwwn79vVf8EDdju1pjg6s97E\n");
		cer.append("6goLc1wKkLgurWZ6WRkdQUtIZgbW+SwnXVIKwL9OHVGJFD7LeWfEjh9Km36gnC95\n");
		cer.append("leqClnKZJxr5ZQ/HjrMnCU18hL0YmIcvYfRkCke4J/7JIux0E40zvRdPNLsBtf1h\n");
		cer.append("ot9vqx8J4trD9F25vKTv75Br+cQ4NL1plUSLlIUmCzi8IYNo+rFrKi5DUeRG3xfF\n");
		cer.append("wtowQrSNZ2C/HF09TFlSAmNwIn1WWJ+jrC1ZigtsoyUwEKqzr4aUi2K/mK+XZPtT\n");
		cer.append("eg==\n");
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