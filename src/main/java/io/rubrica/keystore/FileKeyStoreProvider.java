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

package io.rubrica.keystore;

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
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
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