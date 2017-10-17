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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.logging.Logger;

import javax.security.auth.login.LoginException;

/**
 * Implementacion de <code>KeyStoreProvider</code> para utilizar con
 * dispositivos fisicos tipo PKCS#11 (Token USB, Smart Card, etc).
 *
 * Utiliza internamente la clase <code>sun.security.pkcs11.SunPKCS11</code> para
 * acceder al API de PKCS#11 provisto en Java, por tanto funciona solo con el
 * JVM de Sun Microsystems.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public abstract class PKCS11KeyStoreProvider implements KeyStoreProvider {

	private static final Logger log = Logger.getLogger(PKCS11KeyStoreProvider.class.getName());

	/**
	 * Obtiene la configuracion para el Provider, segun el sistema operativo que
	 * se utilice.
	 * 
	 * @return
	 */
	public abstract String getConfig();

	public KeyStore getKeystore() throws KeyStoreException {
		return getKeystore(null);
	}

	public KeyStore getKeystore(char[] password) throws KeyStoreException {
		InputStream configStream = null;

		try {
			// Crear una instancia de sun.security.pkcs11.SunPKCS11
			configStream = new ByteArrayInputStream(getConfig().getBytes());
			Provider sunPKCS11Provider = this.createSunPKCS11Provider(configStream);
			Security.addProvider(sunPKCS11Provider);

			KeyStore keyStore = KeyStore.getInstance("PKCS11");
			keyStore.load(null, password);
			return keyStore;
		} catch (CertificateException e) {
			throw new KeyStoreException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		} catch (IOException e) {
			throw new KeyStoreException(e);
		} finally {
			if (configStream != null) {
				try {
					configStream.close();
				} catch (IOException e) {
					log.warning(e.getMessage());
				}
			}
		}
	}

	/**
	 * Instancia la clase <code>sun.security.pkcs11.SunPKCS11</code>
	 * dinamicamente, usando Java Reflection.
	 * 
	 * @return una instancia de <code>sun.security.pkcs11.SunPKCS11</code>
	 */
	@SuppressWarnings("unchecked")
	private Provider createSunPKCS11Provider(InputStream configStream) throws KeyStoreException {
		try {
			Class sunPkcs11Class = Class.forName("sun.security.pkcs11.SunPKCS11");
			Constructor pkcs11Constr = sunPkcs11Class.getConstructor(InputStream.class);
			return (Provider) pkcs11Constr.newInstance(configStream);
		} catch (ClassNotFoundException e) {
			throw new KeyStoreException(e);
		} catch (NoSuchMethodException e) {
			throw new KeyStoreException(e);
		} catch (InvocationTargetException e) {
			throw new KeyStoreException(e);
		} catch (IllegalAccessException e) {
			throw new KeyStoreException(e);
		} catch (InstantiationException e) {
			throw new KeyStoreException(e);
		}
	}

	public abstract boolean existeDriver();

	public void logout() throws KeyStoreException {
		InputStream configStream = null;

		try {
			// Crear una instancia de sun.security.pkcs11.SunPKCS11
			configStream = new ByteArrayInputStream(getConfig().getBytes());
			Provider sunPKCS11Provider = this.createSunPKCS11Provider(configStream);
			AuthProvider auth = (AuthProvider) sunPKCS11Provider;

			try {
				auth.logout();
			} catch (LoginException e) {
				throw new KeyStoreException(e);
			}
		} finally {
			if (configStream != null) {
				try {
					configStream.close();
				} catch (IOException e) {
					log.warning(e.getMessage());
				}
			}
		}
	}

	protected static boolean is64bit() {
		return System.getProperty("sun.arch.data.model").contains("64");
	}
}