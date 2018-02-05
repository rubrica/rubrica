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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import io.rubrica.util.Utils;

class OOXMLZipHelper {

	private OOXMLZipHelper() {
	}

	private static final String NAMESPACE_SPEC_NS = "http://www.w3.org/2000/xmlns/";

	private static final String RELATIONSHIPS_SCHEMA = "http://schemas.openxmlformats.org/package/2006/relationships";

	static byte[] outputSignedOfficeOpenXMLDocument(final byte[] ooXmlDocument, final byte[] xmlSignatureFile)
			throws IOException, ParserConfigurationException, SAXException, TransformerException,
			XPathExpressionException {
		final ByteArrayOutputStream signedOOXMLOutputStream = new ByteArrayOutputStream();

		final String signatureZipEntryName = "_xmlsignatures/sig-" + UUID.randomUUID().toString() + ".xml";

		// Copiamos el contenido del OOXML original al OOXML firmado
		// Durante el proceso es necesario modificar ciertos ficheros
		try (final ZipOutputStream zipOutputStream = copyOOXMLContent(ooXmlDocument, signatureZipEntryName,
				signedOOXMLOutputStream);) {
			// Anadimos el fichero de firma XML al paquete OOXML
			zipOutputStream.putNextEntry(new ZipEntry(signatureZipEntryName));
			if (xmlSignatureFile != null) {
				zipOutputStream.write(xmlSignatureFile);
			}
		}

		return signedOOXMLOutputStream.toByteArray();
	}

	private static ZipOutputStream copyOOXMLContent(final byte[] ooXmlDocument, final String signatureZipEntryName,
			final OutputStream signedOOXMLOutputStream) throws IOException, ParserConfigurationException, SAXException,
			TransformerException, XPathExpressionException {
		final ZipOutputStream zipOutputStream = new ZipOutputStream(signedOOXMLOutputStream);
		try (final ZipInputStream zipInputStream = new ZipInputStream(new ByteArrayInputStream(ooXmlDocument));) {
			ZipEntry zipEntry;
			boolean hasOriginSigsRels = false;
			while (null != (zipEntry = zipInputStream.getNextEntry())) {
				zipOutputStream.putNextEntry(new ZipEntry(zipEntry.getName()));
				if ("[Content_Types].xml".equals(zipEntry.getName())) {
					final Document contentTypesDocument = loadDocumentNoClose(zipInputStream);
					final Element typesElement = contentTypesDocument.getDocumentElement();

					// We need to add an Override element.
					final Element overrideElement = contentTypesDocument.createElementNS(
							"http://schemas.openxmlformats.org/package/2006/content-types", "Override");
					overrideElement.setAttribute("PartName", "/" + signatureZipEntryName);
					overrideElement.setAttribute("ContentType",
							"application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml");
					typesElement.appendChild(overrideElement);

					final XPath xpath = XPathFactory.newInstance().newXPath();
					xpath.setNamespaceContext(new NamespaceContext() {

						@Override
						public Iterator<?> getPrefixes(final String namespaceURI) {
							throw new UnsupportedOperationException();
						}

						@Override
						public String getPrefix(final String namespaceURI) {
							throw new UnsupportedOperationException();
						}

						@Override
						public String getNamespaceURI(final String prefix) {
							if (prefix == null) {
								throw new IllegalArgumentException("El prefijo no puede ser nulo");
							}
							if ("xml".equals(prefix)) {
								return XMLConstants.XML_NS_URI;
							}
							if ("tns".equals(prefix)) {
								return "http://schemas.openxmlformats.org/package/2006/content-types";
							}
							return XMLConstants.NULL_NS_URI;
						}
					});

					final XPathExpression exp = xpath.compile("/tns:Types/tns:Default[@Extension='sigs']");
					final NodeList nodeList = (NodeList) exp.evaluate(contentTypesDocument, XPathConstants.NODESET);

					if (0 == nodeList.getLength()) {
						// Add Default element for 'sigs' extension.
						final Element defaultElement = contentTypesDocument.createElementNS(
								"http://schemas.openxmlformats.org/package/2006/content-types", "Default" //$NON-NLS-2$
						);
						defaultElement.setAttribute("Extension", "sigs");
						defaultElement.setAttribute("ContentType",
								"application/vnd.openxmlformats-package.digital-signature-origin");
						typesElement.appendChild(defaultElement);
					}

					writeDocumentNoClosing(contentTypesDocument, zipOutputStream, false);
				} else if ("_rels/.rels".equals(zipEntry.getName())) {
					final Document relsDocument = loadDocumentNoClose(zipInputStream);

					final XPath xpath = XPathFactory.newInstance().newXPath();
					xpath.setNamespaceContext(new NamespaceContext() {

						@Override
						public Iterator<?> getPrefixes(final String namespaceURI) {
							throw new UnsupportedOperationException();
						}

						@Override
						public String getPrefix(final String namespaceURI) {
							throw new UnsupportedOperationException();
						}

						@Override
						public String getNamespaceURI(final String prefix) {
							if (prefix == null) {
								throw new IllegalArgumentException("El prefijo no puede ser nulo");
							}
							if ("xml".equals(prefix)) {
								return XMLConstants.XML_NS_URI;
							}
							if ("tns".equals(prefix)) {
								return RELATIONSHIPS_SCHEMA;
							}
							return XMLConstants.NULL_NS_URI;
						}
					});
					final XPathExpression exp = xpath.compile(
							"/tns:Relationships/tns:Relationship[@Type='http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin']" //$NON-NLS-1$
					);
					final NodeList nodeList = (NodeList) exp.evaluate(relsDocument, XPathConstants.NODESET);

					if (0 == nodeList.getLength()) {
						final Element relationshipElement = relsDocument.createElementNS(RELATIONSHIPS_SCHEMA,
								"Relationship");
						relationshipElement.setAttribute("Id", "rel-id-" + UUID.randomUUID().toString());
						relationshipElement.setAttribute("Type",
								"http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin");
						relationshipElement.setAttribute("Target", "_xmlsignatures/origin.sigs");

						relsDocument.getDocumentElement().appendChild(relationshipElement);
					}

					writeDocumentNoClosing(relsDocument, zipOutputStream, false);
				} else if (zipEntry.getName().startsWith("_xmlsignatures/_rels/")
						&& zipEntry.getName().endsWith(".rels")) {

					hasOriginSigsRels = true;
					final Document originSignRelsDocument = loadDocumentNoClose(zipInputStream);

					final Element relationshipElement = originSignRelsDocument.createElementNS(RELATIONSHIPS_SCHEMA,
							"Relationship");
					relationshipElement.setAttribute("Id", "rel-" + UUID.randomUUID().toString());
					relationshipElement.setAttribute("Type",
							"http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature");
					relationshipElement.setAttribute("Target", new File(signatureZipEntryName).getName());

					originSignRelsDocument.getDocumentElement().appendChild(relationshipElement);

					writeDocumentNoClosing(originSignRelsDocument, zipOutputStream, false);
				} else {
					zipOutputStream.write(Utils.getDataFromInputStream(zipInputStream));
				}
			}

			if (!hasOriginSigsRels) {
				// Add signature relationships document.
				addOriginSigsRels(signatureZipEntryName, zipOutputStream);
				addOriginSigs(zipOutputStream);
			}
		}

		return zipOutputStream;
	}

	private static void addOriginSigs(final ZipOutputStream zipOutputStream) throws IOException {
		zipOutputStream.putNextEntry(new ZipEntry("_xmlsignatures/origin.sigs"));
	}

	private static void addOriginSigsRels(final String signatureZipEntryName, final ZipOutputStream zipOutputStream)
			throws ParserConfigurationException, IOException, TransformerException {
		final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);

		final Document originSignRelsDocument = documentBuilderFactory.newDocumentBuilder().newDocument();

		final Element relationshipsElement = originSignRelsDocument.createElementNS(RELATIONSHIPS_SCHEMA,
				"Relationships");
		relationshipsElement.setAttributeNS(NAMESPACE_SPEC_NS, "xmlns", RELATIONSHIPS_SCHEMA);
		originSignRelsDocument.appendChild(relationshipsElement);

		final Element relationshipElement = originSignRelsDocument.createElementNS(RELATIONSHIPS_SCHEMA,
				"Relationship"); //$NON-NLS-1$
		final String relationshipId = "rel-" + UUID.randomUUID().toString();
		relationshipElement.setAttribute("Id", relationshipId);
		relationshipElement.setAttribute("Type",
				"http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature");

		relationshipElement.setAttribute("Target", new File(signatureZipEntryName).getName());
		relationshipsElement.appendChild(relationshipElement);

		zipOutputStream.putNextEntry(new ZipEntry("_xmlsignatures/_rels/origin.sigs.rels"));
		writeDocumentNoClosing(originSignRelsDocument, zipOutputStream, false);
	}

	static Document loadDocumentNoClose(final InputStream documentInputStream)
			throws ParserConfigurationException, SAXException, IOException {
		final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		try (final InputStream is = new NoCloseInputStream(documentInputStream);) {
			return dbf.newDocumentBuilder().parse(new InputSource(is));
		}
	}

	static void writeDocumentNoClosing(final Document document, final OutputStream documentOutputStream,
			final boolean omitXmlDeclaration) throws TransformerException {
		try (final NoCloseOutputStream outputStream = new NoCloseOutputStream(documentOutputStream);) {
			final Result result = new StreamResult(outputStream);
			final Transformer xformer = TransformerFactory.newInstance().newTransformer();
			if (omitXmlDeclaration) {
				xformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			}
			final Source source = new DOMSource(document);
			xformer.transform(source, result);
		}
	}

	private static class NoCloseOutputStream extends FilterOutputStream {
		NoCloseOutputStream(final OutputStream proxy) {
			super(proxy);
		}

		@Override
		public void close() {
			// Nunca cerramos
		}
	}

	private static class NoCloseInputStream extends FilterInputStream {
		NoCloseInputStream(final InputStream proxy) {
			super(proxy);
		}

		@Override
		public void close() {
			// Se ignoran los errores al cerrar
		}
	}
}