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

package io.rubrica.util;

import java.util.logging.Logger;

/**
 * Utilidades varias.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class OsUtils {

	private static final Logger logger = Logger.getLogger(OsUtils.class.getName());

	public static boolean isWindows() {
		String osName = System.getProperty("os.name");
		String javaVersion = System.getProperty("java.version");
		logger.finer("Operating System:" + osName);
		logger.finer("Java Version:" + javaVersion);

		return (osName.toUpperCase().indexOf("WINDOWS") == 0);
	}

	public static boolean is64Bits() {
		return System.getProperty("os.arch").equals("xmd64");
	}
}