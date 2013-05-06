/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.cert.bce;

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
 * Certificado raiz para pruebas del Banco Central del Ecuador, representado
 * como un objeto <code>X509Certificate</code>.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class BceCaTestCert extends X509Certificate {

	private X509Certificate certificate;

	public BceCaTestCert() {
		super();

		StringBuffer cer = new StringBuffer();
		cer.append("-----BEGIN CERTIFICATE-----\n");
		cer.append("MIIIPjCCBiagAwIBAgIETdwIIzANBgkqhkiG9w0BAQsFADCBzTELMAkGA1UEBhMC\n");
		cer.append("RUMxJzAlBgNVBAoTHkJBTkNPIENFTlRSQUwgREVMIEVDVUFET1IgVEVTVDE8MDoG\n");
		cer.append("A1UECxMzRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFDSU9OLUVD\n");
		cer.append("SUJDRSBURVNUMQ4wDAYDVQQHEwVRVUlUTzFHMEUGA1UEAxM+QVVUT1JJREFEIERF\n");
		cer.append("IENFUlRJRklDQUNJT04gUkFJWiBCQU5DTyBDRU5UUkFMIERFTCBFQ1VBRE9SIFRF\n");
		cer.append("U1QwHhcNMTEwNTI0MTkwNDA0WhcNMzEwNTI0MTkzNDA0WjCBzTELMAkGA1UEBhMC\n");
		cer.append("RUMxJzAlBgNVBAoTHkJBTkNPIENFTlRSQUwgREVMIEVDVUFET1IgVEVTVDE8MDoG\n");
		cer.append("A1UECxMzRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFDSU9OLUVD\n");
		cer.append("SUJDRSBURVNUMQ4wDAYDVQQHEwVRVUlUTzFHMEUGA1UEAxM+QVVUT1JJREFEIERF\n");
		cer.append("IENFUlRJRklDQUNJT04gUkFJWiBCQU5DTyBDRU5UUkFMIERFTCBFQ1VBRE9SIFRF\n");
		cer.append("U1QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDHLbKU+zJrkrEqeWE7\n");
		cer.append("Ff1eLq8LDbzyNXoZ2dyfdlgigGVdZ805p1cwBf+p272FOkW9P9/TSbIA4Uck4hdZ\n");
		cer.append("e9Keeohb/fInTnhq+NsWK8vl7+cLr/uDUxZoth3n9oXKPMJop66E4OYXEiR8BZIq\n");
		cer.append("DGKdJSF12GznAPcqbUwPeFCtcHtEcIxpATFNYflrOBlPXKz07iJfZXBCU9vEvomR\n");
		cer.append("UkAsKtpbwD+VAWRZu/I7jZM79Y38Py3Zurd3k2N7aTnJ098D4ZJQtDoaUEr2fhSY\n");
		cer.append("AFLoxwsmmTZcvQdwzgmEgTtt3MpQJbPgPPwgn1bXG/NMkcAT8NcenTOa45319i9c\n");
		cer.append("kbCjG9OYgtpCaRDgZNo94M0PZkWxF7J4Bc/1aA4xteifHxHtJrGHA7/b+09DVjgz\n");
		cer.append("yFmd4NF2sQzo8qQjSOmYzRx4uWAwe3+HUvdCox40LviQ17GPUnOmdLsR2wGJv/3F\n");
		cer.append("N1RQDvJPZTgkFNuZsuE2Hh8d4gIXrhGERi30BxWA1e4m9DVDl8urv1R8EKj+x/PR\n");
		cer.append("JR4FjkUgpYOPoSGW+SgMT41R2nzcGuggwnFB/u/bJIKY+ehuSjskKwrzaL9eEuUh\n");
		cer.append("YOVB4wOVreUCuFJhp5nen2tK7WihsMcDdq8Q2pY11YOVgx1wmSm9xa0lSSbgP048\n");
		cer.append("tdX/ehS8uly0q/DUtaDf/It1vwIDAQABo4ICIjCCAh4waQYDVR0gBGIwYDBeBgor\n");
		cer.append("BgEEAYKoOwEAMFAwTgYIKwYBBQUHAgEWQmh0dHA6Ly93d3cuZWNpLmJjZS5lYy9y\n");
		cer.append("YWl6L2RlY2xhcmFjaW9uLXByYWN0aWNhcy1jZXJ0aWZpY2FjaW9uLnBkZjARBglg\n");
		cer.append("hkgBhvhCAQEEBAMCAAcwgfYGA1UdHwSB7jCB6zCB6KCB5aCB4qSB3zCB3DELMAkG\n");
		cer.append("A1UEBhMCRUMxJzAlBgNVBAoTHkJBTkNPIENFTlRSQUwgREVMIEVDVUFET1IgVEVT\n");
		cer.append("VDE8MDoGA1UECxMzRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFD\n");
		cer.append("SU9OLUVDSUJDRSBURVNUMQ4wDAYDVQQHEwVRVUlUTzFHMEUGA1UEAxM+QVVUT1JJ\n");
		cer.append("REFEIERFIENFUlRJRklDQUNJT04gUkFJWiBCQU5DTyBDRU5UUkFMIERFTCBFQ1VB\n");
		cer.append("RE9SIFRFU1QxDTALBgNVBAMTBENSTDEwKwYDVR0QBCQwIoAPMjAxMTA1MjQxOTA0\n");
		cer.append("MDRagQ8yMDMxMDUyNDE5MzQwNFowCwYDVR0PBAQDAgEGMB8GA1UdIwQYMBaAFP2N\n");
		cer.append("ek1J7bRjIw5c67uS9Gpsgyr0MB0GA1UdDgQWBBT9jXpNSe20YyMOXOu7kvRqbIMq\n");
		cer.append("9DAMBgNVHRMEBTADAQH/MB0GCSqGSIb2fQdBAAQQMA4bCFY4LjA6NC4wAwIEkDAN\n");
		cer.append("BgkqhkiG9w0BAQsFAAOCAgEAt1Jq1W1zJKh/aLO5VR8KfUdg2reHHBFyLWynbGRK\n");
		cer.append("nzMv0ac9guX1FRI0ZhwqgUUbWrKXjrKs2lGIZO+ybTBC+18NoZ76xLFNj3HP4hy+\n");
		cer.append("sJuHpuk36wfCQn5/0hKyKIqGMCAjuquV895HOJ0aGgiFUYzvgPySww/EVzSEtQTR\n");
		cer.append("q53tiRQh38wdxPc+p39Em8xhAOVzO88MVksA8J6dN5ppYdwGBS6vu/j1Q0Rz8xJ5\n");
		cer.append("D1mahhUcal05dDHsDl/QwPJMCY45LvXDPoIKOmi6pRqINVrtifIi0UsqkOvejtdY\n");
		cer.append("w3cZ37dnUIF87axICrmksqHGCemp6H6KAb4PRWGvZzN5CBw0l3XCUxyC7rHPUJe7\n");
		cer.append("PWWdWTeJ4PB6EQmDrNg4B0YzxFYBeIxjkzyrG9vTC6+ABs/kkOOZv4WQg/q7dMZf\n");
		cer.append("JUV1ogwL9DrUNYP5FUsN2LuM2aaZbptLrUoJopq9vJ5Id1EvAejmrT0O28L2vUUa\n");
		cer.append("qDuftQHYsFLi3PyWHZVj9KOaf/1o0p5z93Rs3fmaPK+hps/N9wOnuafySr4tUn/V\n");
		cer.append("LniJw5alUuGTkdSP6K3PU8oNNdV0hiMOVNJWZtTzW7YCKx1QHa64V26Y6WEggsvL\n");
		cer.append("kUm72Rty55MHGQRk1M7dWRlgcINDEVebcgSAbWGfR7BRXGFqm/bJUn4kMTk4zjQw\n");
		cer.append("A2w=\n");
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

	@Override
	public Set<String> getCriticalExtensionOIDs() {
		return certificate.getCriticalExtensionOIDs();
	}

	@Override
	public byte[] getExtensionValue(String oid) {
		return certificate.getExtensionValue(oid);
	}

	@Override
	public Set<String> getNonCriticalExtensionOIDs() {
		return certificate.getNonCriticalExtensionOIDs();
	}

	@Override
	public boolean hasUnsupportedCriticalExtension() {
		return certificate.hasUnsupportedCriticalExtension();
	}
}