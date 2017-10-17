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
import java.security.cert.CertificateException;
import java.util.logging.Logger;

/**
 * Implementacion de KeyStoreProvider para acceder a Microsoft Crypto API del
 * sistema operativo Microsoft Windows.
 *
 * Utiliza funcionalidad disponible desde el JDK6 en adelante para acceder al MS
 * CAPI.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class WindowsKeyStoreProvider implements KeyStoreProvider {

	private static final Logger logger = Logger
			.getLogger(WindowsKeyStoreProvider.class.getName());

	public KeyStore getKeystore() throws KeyStoreException {
		try {
			KeyStore keyStore = KeyStore.getInstance("Windows-MY");
			keyStore.load(null, null);

			// Corregir bug en el MSCAPI
			if (KeyStoreUtilities.tieneAliasRepetidos(keyStore)) {
				logger.fine("El KeyStore tiene alias repetidos, fixing...");
				KeyStoreUtilities.fixAliases(keyStore);
			}

			return keyStore;
		} catch (NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		} catch (CertificateException e) {
			throw new KeyStoreException(e);
		} catch (IOException e) {
			throw new KeyStoreException(e);
		}
	}

	public KeyStore getKeystore(char[] ignore) throws KeyStoreException {
		return getKeystore();
	}
}