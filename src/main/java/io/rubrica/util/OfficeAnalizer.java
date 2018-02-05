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

package io.rubrica.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import io.rubrica.xml.FileUtils;

/**
 * Clase para el an&aacute;lisis de ficheros OOXML, ODF y Microsoft Office
 * 97/2003.
 */
public final class OfficeAnalizer {

	private OfficeAnalizer() {
		// No permitimos la instanciacion
	}

	private static final String ZIP_MIMETYPE = "application/zip";

	/** MimeTypes reconocidos del formato OOXML. */
	private static final Set<String> OOXML_MIMETYPES = new HashSet<String>(17);

	/** MimeTypes reconocidos del formato ODF. */
	private static final Set<String> ODF_MIMETYPES = new HashSet<String>(15);

	/** Extensiones de fichero asignadas a cada uno de los mimetypes. */
	private static final Map<String, String> FILE_EXTENSIONS = new HashMap<String, String>();

	static {
		// MimeTypes reconocidos del formato OOXML
		OOXML_MIMETYPES.add("application/vnd.ms-word.document.macroEnabled.12");
		OOXML_MIMETYPES.add("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
		OOXML_MIMETYPES.add("application/vnd.ms-word.template.macroEnabled.12");
		OOXML_MIMETYPES.add("application/vnd.openxmlformats-officedocument.wordprocessingml.template");
		OOXML_MIMETYPES.add("application/vnd.ms-powerpoint.template.macroEnabled.12");
		OOXML_MIMETYPES.add("application/vnd.openxmlformats-officedocument.presentationml.template");
		OOXML_MIMETYPES.add("application/vnd.ms-powerpoint.addin.macroEnabled.12");
		OOXML_MIMETYPES.add("application/vnd.ms-powerpoint.slideshow.macroEnabled.12");
		OOXML_MIMETYPES.add("application/vnd.openxmlformats-officedocument.presentationml.slideshow");
		OOXML_MIMETYPES.add("application/vnd.ms-powerpoint.presentation.macroEnabled.12");
		OOXML_MIMETYPES.add("application/vnd.openxmlformats-officedocument.presentationml.presentation");
		OOXML_MIMETYPES.add("application/vnd.ms-excel.addin.macroEnabled.12");
		OOXML_MIMETYPES.add("application/vnd.ms-excel.sheet.binary.macroEnabled.12");
		OOXML_MIMETYPES.add("application/vnd.ms-excel.sheet.macroEnabled.12");
		OOXML_MIMETYPES.add("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
		OOXML_MIMETYPES.add("application/vnd.ms-excel.template.macroEnabled.12");
		OOXML_MIMETYPES.add("application/vnd.openxmlformats-officedocument.spreadsheetml.template");

		// MimeTypes reconocidos del formato ODF
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.text");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.text-template");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.text-web");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.text-master");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.graphics");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.graphics-template");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.presentation");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.presentation-template");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.spreadsheet");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.spreadsheet-template");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.chart");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.formula");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.database");
		ODF_MIMETYPES.add("application/vnd.oasis.opendocument.image");
		ODF_MIMETYPES.add("application/vnd.openofficeorg.extension");

		// Extensiones de fichero
		FILE_EXTENSIONS.put("application/zip", "zip");

		FILE_EXTENSIONS.put("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx");
		FILE_EXTENSIONS.put("application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx");
		FILE_EXTENSIONS.put("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx");

		FILE_EXTENSIONS.put("application/vnd.oasis.opendocument.text", "odt");
		FILE_EXTENSIONS.put("application/vnd.oasis.opendocument.presentation", "odp");
		FILE_EXTENSIONS.put("application/vnd.oasis.opendocument.spreadsheet", "ods");
		FILE_EXTENSIONS.put("application/vnd.oasis.opendocument.graphics", "odg");
		FILE_EXTENSIONS.put("application/vnd.oasis.opendocument.chart", "odc");
		FILE_EXTENSIONS.put("application/vnd.oasis.opendocument.formula", "odf");
		FILE_EXTENSIONS.put("application/vnd.oasis.opendocument.database", "odb");
		FILE_EXTENSIONS.put("application/vnd.oasis.opendocument.image", "odi");
		FILE_EXTENSIONS.put("application/vnd.oasis.opendocument.text-master", "odm");
	}

	private static final Logger logger = Logger.getLogger(OfficeAnalizer.class.getName());

	/**
	 * Devuelve el MimeType correspondiente al documento ofim&aacute;tico
	 * proporcionado (ODF u OOXML). Si el fichero no se corresponde con ninguno de
	 * ellos pero es un Zip se devolver&aacute; el MimeType del Zip
	 * (application/zip) y si no es Zip se devolver&aacute; {@code null}.
	 * 
	 * @param data
	 *            Fichero ODF, OOXML o Microsoft Office 97/2003
	 * @return MimeType.
	 * @throws IOException
	 *             Si no se puede leer el fichero
	 */
	static String getMimeType(final byte[] data) throws IOException {
		ZipFile zipFile = null;
		try {
			zipFile = FileUtils.createTempZipFile(data);
			String mimetype = ZIP_MIMETYPE;
			String tempMimetype = null;
			if (isODFFile(zipFile)) {
				tempMimetype = getODFMimeType(zipFile.getInputStream(zipFile.getEntry("mimetype")));
			} else if (isOOXMLFile(zipFile)) {
				tempMimetype = getOOXMLMimeType(zipFile.getInputStream(zipFile.getEntry("[Content_Types].xml")));
			} else {
				tempMimetype = getMimeTypeOffice97(data);
			}
			if (tempMimetype != null) {
				mimetype = tempMimetype;
			}
			return mimetype;
		} catch (final ZipException e1) {
			logger.warning("El fichero indicado no es un ZIP: " + e1);
		} finally {
			if (zipFile != null) {
				zipFile.close();
			}
		}

		final String retVal = getMimeTypeOffice97(data);

		if (retVal != null) {
			return retVal;
		}
		return "application/octect-stream";

	}

	private static String getMimeTypeOffice97(final byte[] data) {

		// Comprobamos si se trata de un documento de Office 97-2003 con una
		// estructura zip interna
		final String testString = new String(data);

		if (testString.contains("Microsoft Excel")) {
			return "application/vnd.ms-excel";
		}
		if (testString.contains("Microsoft Office Word")) {
			return "application/msword";
		}
		if (testString.contains("Microsoft Office PowerPoint")) {
			return "application/vnd.ms-powerpoint";
		}
		if (testString.contains("Microsoft Project")) {
			return "application/vnd.ms-project";
		}
		if (testString.contains("Microsoft Visio")) {
			return "application/vnd.visio";
		}
		return null;
	}

	/**
	 * Devuelve la extensi&oacute;n correspondiente al documento ofim&aacute;tico
	 * proporcionado (ODF u OOXML). Si el fichero no se corresponde con ninguno de
	 * ellos pero es un Zip se devolver&aacute; la extensi&oacute;n "zip" y si no es
	 * Zip se devolver&aacute; {@code null}.
	 * 
	 * @param zipData
	 *            Fichero ODF u OOXML
	 * @return Extensi&oacute;n.
	 * @throws IOException
	 *             Cuando ocurre alg&uacute;n error en la lectura de los datos.
	 */
	static String getExtension(final byte[] zipData) throws IOException {
		final String mimetype = getMimeType(zipData);
		if (mimetype == null) {
			return null;
		}
		return FILE_EXTENSIONS.get(mimetype);
	}

	/**
	 * Indica si un fichero tiene la estructura de un documento OOXML.
	 * 
	 * @param document
	 *            Fichero a analizar
	 * @return Devuelve <code>true</code> si el fichero era un OOXML,
	 *         <code>false</code> en caso contrario.
	 * @throws IOException
	 *             SI ocurren problemas leyendo el fichero
	 */
	public static boolean isOOXMLDocument(final byte[] document) throws IOException {
		final ZipFile zipFile = FileUtils.createTempZipFile(document);
		final boolean ret = isOOXMLFile(zipFile);
		zipFile.close();
		return ret;
	}

	/**
	 * Indica si un fichero Zip tiene la estructura de un documento OOXML soportado.
	 * 
	 * @param zipFile
	 *            Fichero zip que deseamos comprobar.
	 * @return Devuelve <code>true</code> si el fichero era un OOXML soportado,
	 *         <code>false</code> en caso contrario.
	 */
	private static boolean isOOXMLFile(final ZipFile zipFile) {
		// Comprobamos si estan todos los ficheros principales del documento
		return zipFile.getEntry("[Content_Types].xml") != null && zipFile.getEntry("_rels/.rels") != null
				&& zipFile.getEntry("docProps/app.xml") != null && zipFile.getEntry("docProps/core.xml") != null;
	}

	/**
	 * Recupera el MimeType del XML "[Content_Type].xml" de un OOXML. Si el
	 * documento no es correcto o no se reconoce el Mimetype se devuelve null.
	 * 
	 * @param contentTypeIs
	 *            XML "[Content_Type].xml".
	 * @return Devuelve el MimeType del OOXML o, si no es un OOXML reconocido,
	 *         devuelve {@code null}.
	 */
	public static String getOOXMLMimeType(final InputStream contentTypeIs) {

		final Document doc;
		try {
			doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(contentTypeIs);
		} catch (final Exception e) {
			return null;
		}

		// Obtenemos la raiz
		final Element root = doc.getDocumentElement();
		if (!root.getNodeName().equalsIgnoreCase("Types")) {
			return null;
		}

		Node node = null;
		final NodeList nodes = root.getChildNodes();
		for (int i = 0; i < nodes.getLength(); i++) {
			node = nodes.item(i);
			if (node.getNodeName().equalsIgnoreCase("Override")) {
				final NamedNodeMap nodeAttributes = node.getAttributes();
				Node nodeAttribute = null;
				for (int j = 0; j < nodeAttributes.getLength(); j++) {
					if (nodeAttributes.item(j).getNodeName().equalsIgnoreCase("ContentType")) {
						nodeAttribute = nodeAttributes.item(j);
						break;
					}
				}

				if (nodeAttribute != null) {
					String value = nodeAttribute.getNodeValue();
					if (value.indexOf('.') != -1) {
						value = value.substring(0, value.lastIndexOf('.'));
					}
					if (OOXML_MIMETYPES.contains(value)) {
						return value;
					}
				}
			}
		}
		return null;
	}

	/**
	 * Indica si un fichero tiene la estructura de un documento ODF.
	 * 
	 * @param document
	 *            Fichero a analizar
	 * @return Devuelve <code>true</code> si el fichero era un ODF,
	 *         <code>false</code> en caso contrario.
	 * @throws IOException
	 *             Si ocurren problemas leyendo el fichero
	 */
	public static boolean isODFDocument(final byte[] document) throws IOException {
		final ZipFile zipFile = FileUtils.createTempZipFile(document);
		final boolean ret = isODFFile(zipFile);
		zipFile.close();
		return ret;
	}

	/**
	 * Indica si un fichero Zip tiene la estructura de un documento ODF soportado.
	 * 
	 * @param zipFile
	 *            Fichero zip que deseamos comprobar.
	 * @return Devuelve <code>true</code> si el fichero era un ODF soportado,
	 *         <code>false</code> en caso contrario.
	 */
	private static boolean isODFFile(final ZipFile zipFile) {
		// Comprobamos si estan todos los ficheros principales del documento
		// Se separan las comprobaciones en varios if para no tener una sola
		// sentencia condicional muy larga
		if (zipFile.getEntry("mimetype") == null) {
			return false;
		}
		if (zipFile.getEntry("content.xml") == null) {
			return false;
		}
		if (zipFile.getEntry("meta.xml") == null) {
			return false;
		}
		if (zipFile.getEntry("settings.xml") == null) {
			return false;
		}
		if (zipFile.getEntry("styles.xml") == null) {
			return false;
		}
		if (zipFile.getEntry("META-INF/manifest.xml") == null) {
			return false;
		}
		return true;
	}

	/**
	 * Recupera la extensi&oacute;n apropiada para un documento ODF. Si el fichero
	 * no era un documento ODF soportado, se devolver&aacute; <code>null</code>.
	 * 
	 * @param contentTypeIs
	 *            Fichero del que deseamos obtener la extensi&oacute;n.
	 * @return Extensi&oacute;n del documento.
	 */
	private static String getODFMimeType(final InputStream contentTypeIs) {
		final String contentTypeData;
		try {
			contentTypeData = new String(Utils.getDataFromInputStream(contentTypeIs));
		} catch (final Exception e) {
			return null;
		}
		if (ODF_MIMETYPES.contains(contentTypeData)) {
			return contentTypeData;
		}
		return null;
	}
}