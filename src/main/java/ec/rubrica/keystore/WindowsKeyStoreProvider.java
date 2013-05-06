/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.keystore;

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
 * @author Ricardo Arguello <ricardo@rubrica.ec>
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