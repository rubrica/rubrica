/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.keystore;

import java.io.File;

/**
 * KeyStoreProvider para tokens ePass3003.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class EPass3003KeyStoreProvider extends PKCS11KeyStoreProvider {

	private static final String config;
	private static final String DRIVER_FILE_32_BITS = "/opt/SecurityData_Linux/redist/i386/libshuttle_p11v220.so.1.0.0";

	// FIXME: Detectar arquitectura de sistema operativo
	private static final String DRIVER_FILE_64_BITS = "/opt/SecurityData_Linux/redist/x86_64/libshuttle_p11v220.so.1.0.0";

	static {
		StringBuffer sb = new StringBuffer();
		sb.append("name=ePass3003\n");
		sb.append("library=" + DRIVER_FILE_32_BITS + "\n");
		config = sb.toString();
	}

	@Override
	public String getConfig() {
		return config;
	}

	private static boolean is64bit() {
		return System.getProperty("sun.arch.data.model").contains("64");
	}

	@Override
	public boolean existeDriver() {
		File driver = new File(DRIVER_FILE_32_BITS);
		return driver.exists();
	}
}