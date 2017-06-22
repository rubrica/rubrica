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

package io.rubrica.sign.xades;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.Properties;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import io.rubrica.core.Util;

/** Elemento de estilo XML (XSL) a firmar. */
public final class XmlStyle {

	private static final Logger logger = Logger.getLogger(XmlStyle.class.getName());

	private static final String HTTP_PROTOCOL_PREFIX = "http://";
	private static final String HTTPS_PROTOCOL_PREFIX = "https://";

	private Element element;
	private final String type;
	private final String href;
	private final String encoding;

	/** Crea un estilo XML (XSL) a firmar vac&iacute;o. */
	public XmlStyle() {
		this.element = null;
		this.type = null;
		this.href = null;
		this.encoding = null;
	}

	/**
	 * Crea un estilo XML (XSL) a firmar.
	 * 
	 * @param data
	 *            XML en formato binario
	 * @param headless
	 *            Indica si deben omitirse las interacciones con el usuario
	 *            mediante interfaz gr&aacute;fico
	 * @throws IOException
	 *             Cuando hay errores de entrada / salida
	 * @throws CannotDereferenceException
	 *             Si no se puede obtener el estilo referenciado
	 * @throws IsInnerlException
	 *             Si la referencia apunta a un elemento dentro del propio XML
	 * @throws ReferenceIsNotXmlException
	 *             Cuando el estilo referenciado no est&aacute; en formato XML
	 * @throws javax.xml.transform.TransformerFactoryConfigurationError
	 *             Cuando hay errores de configuraci&oacute; en la
	 *             factor&iacute;a de transformaciones
	 */
	public XmlStyle(byte[] data, boolean headless)
			throws IOException, CannotDereferenceException, IsInnerlException, ReferenceIsNotXmlException {
		Properties p = getStyleSheetHeader(new String(data));
		this.type = p.getProperty("type");
		this.href = p.getProperty("href");

		if (this.type != null && this.href != null) {

			logger.info("Se ha encontrado una hoja de estilo asociada al XML a firmar: tipo=" + this.type
					+ ", referencia=" + this.href);

			Document tmpDoc = dereferenceStyleSheet(this.href, headless);

			// Cuidado!! Solo rellenamos el Elemento DOM si no es HTTP o HTTPS,
			// porque si es accesible remotamente no necesito el elemento, ya
			// que se
			// firma via referencia Externally Detached
			if (!this.href.startsWith(HTTP_PROTOCOL_PREFIX) && !this.href.startsWith(HTTPS_PROTOCOL_PREFIX)) {
				this.element = tmpDoc.getDocumentElement();
			} else {
				this.element = null;
			}

			this.encoding = tmpDoc.getXmlEncoding();
		} else {
			this.encoding = null;
			this.element = null;
		}
	}

	/**
	 * Establece el Elemento DOM con el estilo.
	 * 
	 * @param e
	 *            Elemento DOM con el estilo
	 */
	public void setStyleElement(Element e) {
		this.element = e;
	}

	/**
	 * Obtiene el Elemento DOM con el estilo.
	 * 
	 * @return Elemento DOM con el estilo
	 */
	public Element getStyleElement() {
		return this.element;
	}

	/**
	 * Obtiene el tipo del estilo.
	 * 
	 * @return Tipo del estilo
	 */
	public String getStyleType() {
		return this.type;
	}

	/**
	 * Obtiene la referencia al estilo.
	 * 
	 * @return Referencia al estilo
	 */
	public String getStyleHref() {
		return this.href;
	}

	/**
	 * Obtiene la codificaci&oacute;n del estilo.
	 * 
	 * @return Codificaci&oacute;n del estilo
	 */
	public String getStyleEncoding() {
		return this.encoding;
	}

	/**
	 * Obtiene los par&aacute;metros de la cabecera de definici&oacute;n de la
	 * hoja de estilo de un XML.
	 * 
	 * @param inputXML
	 *            XML de entrada
	 * @return Properties con los par&aacute;metros encontrados en la cabecera,
	 *         o un Properties vac&iacute;o si el XML no declaraba una hoja de
	 *         estilo
	 * @throws IOException
	 *             Si no se puede analizar adecuadamente la cabecera de estilo
	 */
	private static Properties getStyleSheetHeader(final String inputXML) throws IOException {
		final Properties ret = new Properties();
		if (inputXML == null) {
			return ret;
		}
		final int startPos = inputXML.indexOf("<?xml-stylesheet ");
		if (startPos == -1) {
			return ret;
		}

		String xml = inputXML.substring(startPos);
		xml = xml.substring(0, xml.indexOf('>') + 1).replace("<?xml-stylesheet ", "").replace("?>", "")
				.replace(" ", "\n").replace("\"", "").replace("'", "");

		ret.load(new ByteArrayInputStream(xml.getBytes()));
		return ret;
	}

	/**
	 * Dereferencia una hoja de estilo en forma de Documento DOM.
	 * 
	 * @param id
	 *            Identificador de la hoja de estilo
	 * @param headless
	 *            <code>true</code> si <b>no</b> se desea que se pregunte al
	 *            usuario para dereferenciar las hojas de estilo enlazadas con
	 *            rutas locales
	 * @return Documento DOM con la hoja de estilo
	 * @throws CannotDereferenceException
	 *             Si no se puede dereferenciar
	 * @throws IsInnerlException
	 *             Si no se puede dereferenciar por ser una referencia local
	 * @throws ReferenceIsNotXmlException
	 *             Si el objeto dereferenciado no puede transformarse en un
	 *             Documento DOM
	 */
	private static Document dereferenceStyleSheet(String id, boolean headless)
			throws CannotDereferenceException, IsInnerlException, ReferenceIsNotXmlException {
		if (id == null || id.isEmpty()) {
			throw new CannotDereferenceException("La hoja de estilo era nula o vacia");
		}

		byte[] xml = null;

		// Intentamos dereferenciar directamente, cosa que funciona con
		// http://, https:// y file://
		try {
			URI styleURI = Util.createURI(id);
			if (styleURI.getScheme().equals("file")) {
				throw new UnsupportedOperationException("No se aceptan dereferenciaciones directas con file://");
			}
			xml = Util.getDataFromInputStream(Util.loadFile(styleURI));
		} catch (Exception e) {
			// Si no dereferencia puede ser por tres cosas, porque es una
			// referencia interna,
			// porque es una referencia local o porque directamente no se puede
			// dereferenciar

			// Miramos si la referencia es local
			String[] idParts = id.replace(File.separator, "/").split("/");
			String fileName = idParts[idParts.length - 1];

			if (fileName.startsWith("#")) {
				throw new IsInnerlException(e);
			} else {
				throw new CannotDereferenceException(
						"No se ha podido dereferenciar la hoja de estilo '" + id + "': " + e, e);
			}
		}

		try {
			if (xml != null) {
				return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new ByteArrayInputStream(xml));
			}
			throw new CannotDereferenceException("No se ha dereferenciado la hoja de estilo");
		} catch (final Exception e) {
			throw new ReferenceIsNotXmlException(e);
		}
	}
}