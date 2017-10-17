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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

/**
 * Implementacion de <code>KeyStoreProvider</code> para el sistema operativo Mac
 * OS X.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class AppleKeyStoreProvider implements KeyStoreProvider {

	private static final String APPLE_PROVIDER_TYPE = "KeychainStore";
	private static final String APPLE_PROVIDER_NAME = "Apple";

	public KeyStore getKeystore() throws KeyStoreException {
		try {
			KeyStore keyStore = KeyStore.getInstance(APPLE_PROVIDER_TYPE,
					APPLE_PROVIDER_NAME);
			keyStore.load(null, null);
			return keyStore;
		} catch (NoSuchProviderException e) {
			throw new KeyStoreException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		} catch (CertificateException e) {
			throw new KeyStoreException(e);
		} catch (IOException e) {
			throw new KeyStoreException(e);
		}
	}

	public KeyStore getKeystore(char[] password) throws KeyStoreException {
		return getKeystore();
	}
}