/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

/**
 * Utilidades varias.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class OsUtils {

	private static final Logger log = Logger.getLogger(OsUtils.class.getName());

	public static boolean isWindows() {
		String osName = System.getProperty("os.name");
		String javaVersion = System.getProperty("java.version");

		log.finer("Operating System:" + osName);
		log.finer("Java Version:" + javaVersion);

		return (osName.toUpperCase().indexOf("WINDOWS") == 0);
	}

	public static byte[] getBytesFromFile(File file) throws IOException {
		InputStream is = new FileInputStream(file);
		long length = file.length();

		if (length > Integer.MAX_VALUE) {
			throw new IOException("Archivo demasiado grande!");
		}

		byte[] bytes = new byte[(int) length];
		int offset = 0;
		int numRead = 0;

		while (offset < bytes.length
				&& (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
			offset += numRead;
		}

		if (offset < bytes.length) {
			throw new IOException("No se pudo leer el archivo completo: "
					+ file.getName());
		}

		is.close();
		return bytes;
	}

	public static byte[] getBytesFromInputStream(InputStream is)
			throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int nRead;
		byte[] data = new byte[16384];

		while ((nRead = is.read(data, 0, data.length)) != -1) {
			buffer.write(data, 0, nRead);
		}

		buffer.flush();
		return buffer.toByteArray();
	}

	public static boolean is64Bits() {
		return System.getProperty("os.arch").equals("xmd64");
	}
}