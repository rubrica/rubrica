/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.logging.Logger;

/**
 * Implementacion de KeyStoreProvider para leer de un archivo.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class FileKeyStoreProvider implements KeyStoreProvider {

	private static final Logger log = Logger
			.getLogger(FileKeyStoreProvider.class.getName());

	private File keyStoreFile;

	public FileKeyStoreProvider(File keyStoreFile) {
		this.keyStoreFile = keyStoreFile;
	}

	public FileKeyStoreProvider(String keyStoreFile) {
		this.keyStoreFile = new File(keyStoreFile);
	}

	public KeyStore getKeystore() throws KeyStoreException {
		return getKeystore(null);
	}

	public KeyStore getKeystore(char[] password) throws KeyStoreException {
		InputStream input = null;
		try {
			input = new FileInputStream(keyStoreFile);
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(input, password);
			return keyStore;
		} catch (FileNotFoundException e) {
			throw new KeyStoreException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		} catch (CertificateException e) {
			throw new KeyStoreException(e);
		} catch (IOException e) {
			throw new KeyStoreException(e);
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
					log.warning(e.getMessage());
				}
			}
		}
	}
}