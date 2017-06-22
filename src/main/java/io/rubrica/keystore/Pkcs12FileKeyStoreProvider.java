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

/**
 * Implementacion de KeyStoreProvider para archivos PKCS#12.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class Pkcs12FileKeyStoreProvider implements KeyStoreProvider {

	private File pkcs12File;

	public Pkcs12FileKeyStoreProvider(File pkcs12File) {
		this.pkcs12File = pkcs12File;
	}

	public KeyStore getKeystore() throws KeyStoreException {
		return getKeystore(null);
	}

	public KeyStore getKeystore(char[] password) throws KeyStoreException {
		InputStream inputStream = null;
		try {
			KeyStore kspkcs12 = KeyStore.getInstance("PKCS12");
			inputStream = new FileInputStream(pkcs12File);
			kspkcs12.load(inputStream, password);
			return kspkcs12;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new KeyStoreException(e);
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
				}
			}
		}
	}
}