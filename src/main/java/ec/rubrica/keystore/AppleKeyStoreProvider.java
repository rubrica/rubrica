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
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

/**
 * Implementacion de <code>KeyStoreProvider</code> para el sistema operativo Mac
 * OS X.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
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