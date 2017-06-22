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

package io.rubrica.xml;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.logging.Logger;
import java.util.zip.ZipFile;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;

/** Clase con m&eacute;todos para el trabajo con ficheros. */
public final class FileUtils {

	private static final Logger logger = Logger.getLogger(FileUtils.class.getName());

	private FileUtils() {
		// No permitimos la instanciacion
	}

	private static final String SHORTENER_ELLIPSE = "...";

	/**
	 * Crea un fichero ZIP en disco apto para manejarse.
	 * 
	 * @param zipFileData
	 *            Los datos del zip.
	 * @return Fichero Zip.
	 * @throws java.util.zip.ZipException
	 *             Cuando los datos no eran realmente un Zip.
	 * @throws IOException
	 *             Cuando ocurre un error al leer los datos o crear el temporal
	 *             para abrir el Zip.
	 */
	public static ZipFile createTempZipFile(final byte[] zipFileData) throws IOException {

		// Creamos un fichero temporal
		final File tempFile = File.createTempFile("afirmazip", null); //$NON-NLS-1$
		final FileOutputStream fos = new FileOutputStream(tempFile);
		fos.write(zipFileData);
		fos.flush();
		fos.close();
		tempFile.deleteOnExit();
		return new ZipFile(tempFile);
	}

	/**
	 * Comprueba si los datos proporcionados son un XML v&aacute;lido.
	 * 
	 * @param data
	 *            Datos a evaluar.
	 * @return {@code true} cuando los datos son un XML bien formado.
	 *         {@code false} en caso contrario.
	 */
	public static boolean isXML(final byte[] data) {

		final SAXParserFactory factory = SAXParserFactory.newInstance();
		factory.setValidating(false);
		factory.setNamespaceAware(true);

		try {
			final SAXParser parser = factory.newSAXParser();
			final XMLReader reader = parser.getXMLReader();
			reader.setErrorHandler(new ErrorHandler() {
				@Override
				public void warning(final SAXParseException e) {
					log(e);
				}

				@Override
				public void fatalError(final SAXParseException e) {
					log(e);
				}

				@Override
				public void error(final SAXParseException e) {
					log(e);
				}

				private void log(final Exception e) {
					logger.fine("El documento no es un XML: " + e); //$NON-NLS-1$ //$NON-NLS-2$
				}
			});
			reader.parse(new InputSource(new ByteArrayInputStream(data)));
		} catch (final Exception e) {
			return false;
		}
		return true;
	}
}