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

package io.rubrica.sign.ooxml;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import io.rubrica.core.RubricaException;

/**
 * Clase para la lectura de los content types declarados en un documento OOXML y
 * la identificaci&oacute;n del content type de un fichero en base a ellos.
 */
final class ContentTypeManager {

	private final Map<String, String> defaultContentTypes = new HashMap<>();
	private final Map<String, String> overrideContentTypes = new HashMap<>();

	private static final DocumentBuilderFactory DOC_FACTORY = DocumentBuilderFactory.newInstance();
	static {
		DOC_FACTORY.setNamespaceAware(true);
	}

	private static final String SLASH = "/";

	private static final Logger logger = Logger.getLogger(ContentTypeManager.class.getName());

	/**
	 * Crea un ContentTypeManager que nos permitira conocer el contentType asociado
	 * a cada elemento del documento.
	 * 
	 * @param contentTypeIs
	 *            Flujo de datos de entrada del fichero [Content_Types].xml
	 * @throws SAXException
	 *             Cuando el XML esta mal formado.
	 * @throws IOException
	 *             Cuando ocurre un error al leer el XML.
	 * @throws ParserConfigurationException
	 *             Cuando no se puede crear el constructor de XML.
	 */
	ContentTypeManager(final InputStream contentTypeIs) throws SAXException, IOException, ParserConfigurationException {

		final Document contentTypeDocument = loadDocument(contentTypeIs);
		final NodeList nodeList = contentTypeDocument.getChildNodes();

		if (nodeList.getLength() > 0) {
			// Nodo Types
			Node typeNode = nodeList.item(0);
			final NodeList typeList = typeNode.getChildNodes();

			// Nodos contenidos en Types
			for (int i = 0; i < typeList.getLength(); i++) {
				try {
					typeNode = typeList.item(i);
					if (typeNode.getNodeType() != Node.ELEMENT_NODE) {
						continue;
					}
					if ("Default".equals(typeNode.getNodeName())) {
						final NamedNodeMap attNodes = typeNode.getAttributes();
						this.defaultContentTypes.put(getAttributeValue(attNodes, "Extension"),
								getAttributeValue(attNodes, "ContentType"));
					} else if ("Override".equals(typeNode.getNodeName())) {
						final NamedNodeMap attNodes = typeNode.getAttributes();
						this.overrideContentTypes.put(getAttributeValue(attNodes, "PartName"),
								getAttributeValue(attNodes, "ContentType"));
					}
				} catch (RubricaException e) {
					logger.warning("Se encontro un nodo en el [Content_Types].xml no valido: " + e);
					continue;
				}
			}
		}
	}

	/**
	 * Convierte el <code>InputStream</code> de un XML en un DOM Document.
	 * 
	 * @param documentInputStream
	 *            Fujo del lectura del XML.
	 * @return Documento DOM.
	 * @throws IOException
	 *             Si hay problemas en el tratamiento de los datos del flujo.
	 * @throws SAXException
	 *             Si hay problemas en el tratamiento del XML.
	 * @throws ParserConfigurationException
	 *             Si hay problemas con el anlizador XML por defecto.
	 */
	private static Document loadDocument(final InputStream documentInputStream)
			throws ParserConfigurationException, SAXException, IOException {
		return getNewDocumentBuilder().parse(documentInputStream);
	}

	/**
	 * Devuelve una nueva instancia del <code>DocumentBuilder</code>.
	 * 
	 * @return Nueva instancia del <code>DocumentBuilder</code>.
	 * @throws ParserConfigurationException
	 *             Si hay problemas en el proceso de obtenci&oacute;n.
	 */
	private static DocumentBuilder getNewDocumentBuilder() throws ParserConfigurationException {
		return DOC_FACTORY.newDocumentBuilder();
	}

	/**
	 * Recupera el valor de un atributo.
	 * 
	 * @param nodeMap
	 *            Conjunto de nodos sobre los que realizar la b&uacute;squeda.
	 * @param attrName
	 *            Nombre el atributo a recuperar.
	 * @return Valor del atributo.
	 * @throws AOException
	 *             Cuando el nodo o el atributo no existen.
	 */
	private static String getAttributeValue(final NamedNodeMap nodeMap, final String attrName) throws RubricaException {
		if (nodeMap == null) {
			throw new RubricaException("El nodo no contenia atributos");
		}
		final Node attNode = nodeMap.getNamedItem(attrName);
		if (attNode == null) {
			throw new RubricaException("No existe el atributo: " + attrName);
		}
		return attNode.getNodeValue();
	}

	/**
	 * Recupera el ContentType correspondiente a un fichero interno del OOXML.
	 * 
	 * @param partName
	 *            Ruta de fichero.
	 * @return ContentType definido para ese fichero.
	 */
	String getContentType(final String partName) {
		String partNameFix;
		if (!partName.startsWith(SLASH)) {
			partNameFix = SLASH.concat(partName);
		} else {
			partNameFix = partName;
		}

		if (this.overrideContentTypes.containsKey(partNameFix)) {
			return this.overrideContentTypes.get(partNameFix);
		}

		final String ext = getExtension(partNameFix);
		if (ext != null && this.defaultContentTypes.containsKey(ext)) {
			return this.defaultContentTypes.get(ext);
		}

		return null;
	}

	/**
	 * Devuelve la extendion de un nombre de fichero.
	 * 
	 * @param partName
	 *            Ruta del fichero.
	 * @return Extension o {@code null} si no la hay.
	 */
	private static String getExtension(final String partName) {
		final int dotPos = partName.lastIndexOf('.');
		if (dotPos == -1 || dotPos == partName.length() - 1) {
			return null;
		}
		return partName.substring(dotPos + 1);
	}
}