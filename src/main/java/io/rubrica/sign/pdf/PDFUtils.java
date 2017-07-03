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

package io.rubrica.sign.pdf;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfReader;

import io.rubrica.core.AliasesNotFoundException;
import io.rubrica.core.PrivateKeyAndCertificateChain;

/**
 * Clase utilitaria para firmar PDFs.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 * @deprecated
 */
public class PDFUtils {
	private static final Logger logger = Logger.getLogger(PDFUtils.class.getName());

	public static boolean yaEstaFirmado(byte[] archivoPDF) {
		try {
			// Verificar si ya esta firmado?
			PdfReader reader = new PdfReader(archivoPDF);
			AcroFields fields = reader.getAcroFields();

			@SuppressWarnings("unchecked")
			ArrayList<String> nombreLista = fields.getSignatureNames();

			for (String nombre : nombreLista) {
				System.out.println("Firmante=" + nombre);
			}

			return (nombreLista.size() == 1);
		} catch (IOException e) {
			throw new RuntimeException(e); // FIXME
		}
	}

	public static PrivateKeyAndCertificateChain[] getList(KeyStore keyStore) {
		List<PrivateKeyAndCertificateChain> privateKeys = new ArrayList<PrivateKeyAndCertificateChain>();
		try {
			Field field = keyStore.getClass().getDeclaredField("keyStoreSpi");
			field.setAccessible(true);
			KeyStoreSpi keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

			// Keystore de Windows
			if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
				String alias, hashCode;
				X509Certificate[] certificates;

				field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
				field.setAccessible(true);
				Collection entries = (Collection) field.get(keyStoreVeritable);

				int i = 1;
				for (Object entry : entries) {
					field = entry.getClass().getDeclaredField("certChain");
					field.setAccessible(true);
					certificates = (X509Certificate[]) field.get(entry);

					X509Certificate certificate = certificates[0];
					boolean[] keyUsage = certificate.getKeyUsage();

					if (keyUsage[0]) {
						hashCode = Integer.toString(certificates[0].hashCode());

						// Alias
						field = entry.getClass().getDeclaredField("alias");
						field.setAccessible(true);
						alias = (String) field.get(entry);
						alias = alias + "(" + i++ + ")";

						// PrivateKey
						field = entry.getClass().getDeclaredField("privateKey");
						field.setAccessible(true);
						PrivateKey key = (PrivateKey) field.get(entry);

						PrivateKeyAndCertificateChain p = new PrivateKeyAndCertificateChain(alias + " - " + i++, key,
								certificates);
						privateKeys.add(p);
					}
				}
			}

			return (PrivateKeyAndCertificateChain[]) privateKeys
					.toArray(new PrivateKeyAndCertificateChain[privateKeys.size()]);
		} catch (SecurityException e) {
			throw new RuntimeException(e);
		} catch (NoSuchFieldException e) {
			throw new RuntimeException(e);
		} catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	public static String getSigningAlias(KeyStore keyStore, char[] privateKeyPassword) {
		try {
			Enumeration<String> aliases = keyStore.aliases();

			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				Key key = keyStore.getKey(alias, privateKeyPassword);

				if (key instanceof PrivateKey) {
					Certificate[] certs = keyStore.getCertificateChain(alias);
					if (certs.length >= 1) {
						Certificate cert = certs[0];
						if (cert instanceof X509Certificate) {
							X509Certificate signerCertificate = (X509Certificate) cert;
							boolean[] keyUsage = signerCertificate.getKeyUsage();
							// Digital Signature Key Usage:
							if (keyUsage[0]) {
								return alias;
							}
						}
					}
				}
			}

			throw new RuntimeException("No hay llave privada para firmar!");
		} catch (KeyStoreException e) {
			throw new RuntimeException(e); // FIXME
		} catch (UnrecoverableKeyException e) {
			throw new RuntimeException(e); // FIXME
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e); // FIXME
		}
	}

	public static byte[] getBytesFromFile(File file) throws IOException {
		try (InputStream is = new FileInputStream(file)) {
			long length = file.length();

			if (length > Integer.MAX_VALUE) {
				throw new IOException("Archivo demasiado grande!");
			}

			byte[] bytes = new byte[(int) length];
			int offset = 0;
			int numRead = 0;

			while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
				offset += numRead;
			}

			if (offset < bytes.length) {
				throw new IOException("No se pudo leer el archivo completo: " + file.getName());
			}

			return bytes;
		}
	}

	public static String getSigningAlias(KeyStore keyStore) throws AliasesNotFoundException {

		try {
			Enumeration<String> aliases = keyStore.aliases();
			logger.info("aliases=" + aliases.toString());

			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				logger.info("alias=" + alias);
				Key key = keyStore.getKey(alias, null);

				if (key instanceof PrivateKey) {
					Certificate[] certs = keyStore.getCertificateChain(alias);
					if (certs.length >= 1) {
						Certificate cert = certs[0];
						if (cert instanceof X509Certificate) {
							X509Certificate signerCertificate = (X509Certificate) cert;
							logger.info(" **** cert=" + signerCertificate);
							boolean[] keyUsage = signerCertificate.getKeyUsage();
							// Digital Signature Key Usage:
							if (keyUsage[0]) {
								return alias;
							}
						}
					}
				}
			}

			throw new AliasesNotFoundException("No hay llave privada para firmar!");
		} catch (KeyStoreException e) {
			throw new RuntimeException(e); // FIXME
		} catch (UnrecoverableKeyException e) {
			throw new RuntimeException(e); // FIXME
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e); // FIXME
		}
	}
}