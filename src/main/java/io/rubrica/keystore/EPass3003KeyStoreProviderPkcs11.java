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
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;

/**
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class EPass3003KeyStoreProviderPkcs11 implements KeyStoreProvider {

	private static String windowsDir_iKey = "name = SmartCard\nlibrary = /opt/SecurityData_Linux/redist/x86_64/libshuttle_p11v220.so.1.0.0 \ndisabledMechanisms = { CKM_SHA1_RSA_PKCS  } \n showInfo = true";
	private static final byte[] PKCS11_CONFIG_IKEY = windowsDir_iKey.getBytes();
	private static final String SUN_PKCS11_PROVIDER_CLASS = "sun.security.pkcs11.SunPKCS11";
	private AuthProvider aprov;

	private static final Logger logger = Logger.getLogger(EPass3003KeyStoreProviderPkcs11.class.getName());

	/**
	 * <code> getKeystore </code> Esta funcion se utiliza para obtener el
	 * keystore de java para manejar luego la clave privada y los certificados
	 * dentro del token
	 * 
	 * @param password
	 *            Se pasa la clave del token
	 * @return
	 * @throws java.security.KeyStoreException
	 */
	public KeyStore getKeystore(char[] password) throws KeyStoreException {
		try {
			// empieza intentando con eToken
			InputStream configStream = new ByteArrayInputStream(PKCS11_CONFIG_IKEY);

			Provider sunPKCS11Provider = this.createSunPKCS11Provider(configStream);
			Security.addProvider(sunPKCS11Provider);

			KeyStore.Builder ksBuilder = KeyStore.Builder.newInstance("PKCS11", null,
					new KeyStore.CallbackHandlerProtection(new SimpleCallbackHandler2(null, password)));

			KeyStore ks = ksBuilder.getKeyStore();

			// Controlar mejor el logout del token
			aprov = (AuthProvider) Security.getProvider(sunPKCS11Provider.getName());
			aprov.setCallbackHandler(new SimpleCallbackHandler2(null, password));

			try {
				aprov.login(null, null);
				return ks;
			} catch (LoginException ex) {
				logger.log(Level.SEVERE, null, ex);
				throw new LoginException(ex.getMessage());
			}
		} catch (LoginException e) {
			logger.log(Level.SEVERE, null, e);
			System.out.println("error en el loginExcep" + e);
			throw new KeyStoreException(e);
		}
	}

	/**
	 * <code> logout </code> Esta función permite limpiar de memoria el
	 * keystore.
	 * 
	 * @throws javax.security.auth.login.LoginException
	 */
	public void logout() throws LoginException {
		this.aprov.logout();
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
			Class sunPkcs11Class = Class.forName(SUN_PKCS11_PROVIDER_CLASS);
			Constructor pkcs11Constr = sunPkcs11Class.getConstructor(InputStream.class);
			Provider pkcs11Provider = (Provider) pkcs11Constr.newInstance(configStream);
			return pkcs11Provider;
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

	public KeyStore getKeystore() throws KeyStoreException {
		throw new UnsupportedOperationException("Not supported yet.");
	}
}

class SimpleCallbackHandler2 implements CallbackHandler {
	private String username;
	private char[] password;

	public SimpleCallbackHandler2(String username, char[] password) {
		this.username = username;
		this.password = password;
	}

	public void handle(Callback[] callbacks) {
		for (Callback callback : callbacks) {
			if (callback instanceof NameCallback) {
				((NameCallback) callback).setName(username);
			} else if (callback instanceof PasswordCallback) {
				((PasswordCallback) callback).setPassword(password);
			}
		}
	}
}