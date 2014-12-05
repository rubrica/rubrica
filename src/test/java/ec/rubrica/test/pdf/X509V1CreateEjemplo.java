package ec.rubrica.test.pdf;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

@SuppressWarnings("deprecation")
public class X509V1CreateEjemplo {
	static {
		BouncyCastleProvider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(prov);
	}

	public static X509Certificate generateV1Certificate(KeyPair pair)
			throws InvalidKeyException, NoSuchProviderException,
			SignatureException {
		// generate the certificate
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
		certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		return certGen.generateX509Certificate(pair.getPrivate());
	}

}
