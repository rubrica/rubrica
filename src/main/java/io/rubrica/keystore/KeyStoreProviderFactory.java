/*
 * Copyright 2009-2018 Rubrica
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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Clase utilitaria para instanciar las implementaciones de KeyStoreProvider
 * disponibles.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class KeyStoreProviderFactory {

	public static final String WINDOWS = "WINDOWS";
	public static final String LINUX = "LINUX";
	public static final String MACOS = "MACOS";

	private static final Map<String, List<KeyStoreProvider>> lista = new HashMap<String, List<KeyStoreProvider>>();

	static {
		List<KeyStoreProvider> windows = new ArrayList<KeyStoreProvider>();
		windows.add(new WindowsKeyStoreProvider());
		lista.put(WINDOWS, windows);
	}

	static {
		List<KeyStoreProvider> linux = new ArrayList<KeyStoreProvider>();
		linux.add(new SafenetIKey2032LinuxKeyStoreProvider());
		linux.add(new SafenetLinuxKeyStoreProvider());
		linux.add(new Bit4idLinuxKeyStoreProvider());
		linux.add(new EPass2003LinuxKeyStoreProvider());
		linux.add(new EPass3003LinuxKeyStoreProvider());
		lista.put(LINUX, linux);
	}

	static {
		List<KeyStoreProvider> macOS = new ArrayList<KeyStoreProvider>();
		macOS.add(new AppleKeyStoreProvider());
		macOS.add(new SafenetAppleKeyStoreProvider());
		macOS.add(new EPass2003AppleKeyStoreProvider());
		macOS.add(new EPass3003AppleKeyStoreProvider());
		macOS.add(new Bit4IdAppleKeyStoreProvider());
		lista.put(MACOS, macOS);
	}

	public static List<KeyStoreProvider> getKeyStoreProviderList(String os) {
		return lista.get(os);
	}

	public static List<KeyStoreProvider> getKeyStoreProviderList() {
		if (isWindows()) {
			return lista.get(WINDOWS);
		} else if (isLinux()) {
			return lista.get(LINUX);
		} else if (isMac()) {
			return lista.get(MACOS);
		}

		throw new RuntimeException("Sistema operativo no soportado");
	}

	public static KeyStore getKeyStore(String clave) {
		List<KeyStoreProvider> ksps = getKeyStoreProviderList();
		return getKeyStore(ksps, clave);
	}

	public static KeyStore getKeyStore(List<KeyStoreProvider> providers, String clave) {
		char[] password = (clave != null) ? clave.toCharArray() : null;
		KeyStore keyStore = null;
		KeyStoreException exception = null;

		for (KeyStoreProvider keyStoreProvider : providers) {
			try {
				if (keyStoreProvider instanceof PKCS11KeyStoreProvider) {
					PKCS11KeyStoreProvider pkcs11 = (PKCS11KeyStoreProvider) keyStoreProvider;
					if (pkcs11.existeDriver()) {
						keyStore = keyStoreProvider.getKeystore(password);
					}
				} else {
					keyStore = keyStoreProvider.getKeystore(password);
				}
			} catch (KeyStoreException e) {
				exception = e;
			}
		}

		if (keyStore != null) {
			return keyStore;
		}

		if (exception != null) {
			return null;
		} else {
			throw new RuntimeException("Error al buscar token");
		}
	}

	public static boolean isLinux() {
		String osName = System.getProperty("os.name");
		return (osName.toUpperCase().indexOf("LINUX") == 0);
	}

	public static boolean isWindows() {
		String osName = System.getProperty("os.name");
		return (osName.toUpperCase().indexOf("WINDOWS") == 0);
	}

	public static boolean isMac() {
		String osName = System.getProperty("os.name");
		return (osName.toUpperCase().indexOf("MAC OS X") == 0);
	}
}