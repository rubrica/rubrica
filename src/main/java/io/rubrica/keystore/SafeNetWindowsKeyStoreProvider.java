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

/**
 * Implementacion de KeyStoreProvider para acceder al keystore del sistema
 * operativo Microsoft Windows.
 *
 * Funciona en JDK 5, accede a las librerias PKCS#11 del sistema operativo.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class SafeNetWindowsKeyStoreProvider extends PKCS11KeyStoreProvider {

	private static final String CONFIG;
	private static final String DRIVER_FILE = "C:\\WINDOWS\\SYSTEM32\\dkck201.dll";

	static {
		StringBuffer sb = new StringBuffer();
		sb.append("name=Safenetikey2032\n");
		sb.append("library=" + DRIVER_FILE + "\n");
		sb.append("disabledMechanisms={ CKM_SHA1_RSA_PKCS }");
		CONFIG = sb.toString();
	}

	@Override
	public String getConfig() {
		return CONFIG;
	}

	@Override
	public boolean existeDriver() {
		File driver = new File(DRIVER_FILE);
		return driver.exists();
	}
}