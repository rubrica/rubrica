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
 * KeyStoreProvider para tokens ePass3003.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class EPass3003KeyStoreProvider extends PKCS11KeyStoreProvider {

	private static final String CONFIG;
	private static final String DRIVER_FILE_32_BITS = "/opt/SecurityData_Linux/redist/i386/libshuttle_p11v220.so.1.0.0";
	private static final String DRIVER_FILE_64_BITS = "/opt/SecurityData_Linux/redist/x86_64/libshuttle_p11v220.so.1.0.0";

	static {
		StringBuffer sb = new StringBuffer();
		sb.append("name=ePass3003\n");
		sb.append("library=").append(is64bit() ? DRIVER_FILE_64_BITS : DRIVER_FILE_32_BITS).append("\n");
		CONFIG = sb.toString();
	}

	@Override
	public String getConfig() {
		return CONFIG;
	}

	@Override
	public boolean existeDriver() {
		File driver = is64bit() ? new File(DRIVER_FILE_64_BITS) : new File(DRIVER_FILE_32_BITS);
		return driver.exists();
	}
}