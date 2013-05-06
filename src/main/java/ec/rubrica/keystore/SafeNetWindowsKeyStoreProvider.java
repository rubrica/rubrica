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
 * Implementacion de KeyStoreProvider para acceder al keystore del sistema
 * operativo Microsoft Windows.
 * 
 * Funciona en JDK 5, accede a las librerias PKCS#11 del sistema operativo.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class SafeNetWindowsKeyStoreProvider extends PKCS11KeyStoreProvider {

	private static final String config;
	private static final String DRIVER_FILE = "C:\\WINDOWS\\SYSTEM32\\dkck201.dll";

	static {
		StringBuffer sb = new StringBuffer();
		sb.append("name=Safenetikey2032\n");
		sb.append("library=" + DRIVER_FILE + "\n");
		sb.append("disabledMechanisms={ CKM_SHA1_RSA_PKCS }");
		config = sb.toString();
	}

	@Override
	public String getConfig() {
		return config;
	}

	@Override
	public boolean existeDriver() {
		File driver = new File(DRIVER_FILE);
		return driver.exists();
	}
}