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

package io.rubrica.sign.ooxml.relprovider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.XMLConstants;
import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
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
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Implementaci&oacute;n JSR105 de la transformaci&oacute;n
 * RelationshipTransform. <a href=
 * "http://openiso.org/Ecma/376/Part2/12.2.4#26">http://openiso.org/Ecma/376/Part2/12.2.4#26</a>
 */
public class RelationshipTransformService extends TransformService {

	private static final Logger logger = Logger.getLogger(RelationshipTransformService.class.getName());

	private static final String NAMESPACE_SPEC_NS = "http://www.w3.org/2000/xmlns/";
	private static final String SIGNATURE_SPEC_NS = "http://www.w3.org/2000/09/xmldsig#";

	/** URI de declaraci&oacute;n de la transformaci&oacute;n. */
	public static final String TRANSFORM_URI = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";

	private List<String> sourceIds;

	/** Crea el servicio de la transformaci&oacute;n RelationshipTransform. */
	public RelationshipTransformService() {
		super();
		this.sourceIds = new LinkedList<>();
	}

	/** {@inheritDoc} */
	@Override
	public void init(TransformParameterSpec params) throws InvalidAlgorithmParameterException {
		if (!(params instanceof RelationshipTransformParameterSpec)) {
			throw new InvalidAlgorithmParameterException();
		}
		RelationshipTransformParameterSpec relParams = (RelationshipTransformParameterSpec) params;
		for (String sourceId : relParams.getSourceIds()) {
			this.sourceIds.add(sourceId);
		}
	}

	/** {@inheritDoc} */
	@Override
	public void init(XMLStructure parent, XMLCryptoContext context) throws InvalidAlgorithmParameterException {

		DOMStructure domParent = (DOMStructure) parent;
		Node parentNode = domParent.getNode();
		try {
			toString(parentNode);
		} catch (TransformerException e) {
			throw new InvalidAlgorithmParameterException(e);
		}

		NodeList nodeList;
		try {
			XPath xpath = XPathFactory.newInstance().newXPath();
			xpath.setNamespaceContext(new NamespaceContext() {

				@Override
				public Iterator<?> getPrefixes(String namespaceURI) {
					throw new UnsupportedOperationException();
				}

				@Override
				public String getPrefix(String namespaceURI) {
					throw new UnsupportedOperationException();
				}

				@Override
				public String getNamespaceURI(String prefix) {
					if (prefix == null) {
						throw new IllegalArgumentException("El prefijo no puede ser nulo");
					}
					if ("xml".equals(prefix)) { //$NON-NLS-1$
						return XMLConstants.XML_NS_URI;
					}
					if ("ds".equals(prefix)) { //$NON-NLS-1$
						return SIGNATURE_SPEC_NS;
					}
					if ("mdssi".equals(prefix)) { //$NON-NLS-1$
						return "http://schemas.openxmlformats.org/package/2006/digital-signature";
					}
					return XMLConstants.NULL_NS_URI;
				}
			});
			XPathExpression exp = xpath.compile("mdssi:RelationshipReference/@SourceId");
			nodeList = (NodeList) exp.evaluate(parentNode, XPathConstants.NODESET);
		} catch (Exception e) {
			logger.severe("Error en la transformacion XPath: " + e);
			throw new InvalidAlgorithmParameterException(e);
		}
		if (0 == nodeList.getLength()) {
			logger.warning("no RelationshipReference/@SourceId parameters present");
		}
		for (int nodeIdx = 0; nodeIdx < nodeList.getLength(); nodeIdx++) {
			Node node = nodeList.item(nodeIdx);
			String sourceId = node.getTextContent();
			this.sourceIds.add(sourceId);
		}
	}

	/** {@inheritDoc} */
	@Override
	public void marshalParams(XMLStructure parent, XMLCryptoContext context) {
		DOMStructure domParent = (DOMStructure) parent;
		Node parentNode = domParent.getNode();
		Element parentElement = (Element) parentNode;
		parentElement.setAttributeNS(NAMESPACE_SPEC_NS, "xmlns:mdssi",
				"http://schemas.openxmlformats.org/package/2006/digital-signature");
		Document document = parentNode.getOwnerDocument();
		for (String sourceId : this.sourceIds) {
			Element relationshipReferenceElement = document.createElementNS(
					"http://schemas.openxmlformats.org/package/2006/digital-signature", "mdssi:RelationshipReference");
			relationshipReferenceElement.setAttribute("SourceId", sourceId);
			parentElement.appendChild(relationshipReferenceElement);
		}
	}

	/** {@inheritDoc} */
	@Override
	public AlgorithmParameterSpec getParameterSpec() {
		return null;
	}

	/** {@inheritDoc} */
	@Override
	public Data transform(Data data, XMLCryptoContext context) throws TransformException {
		OctetStreamData octetStreamData = (OctetStreamData) data;

		Document relationshipsDocument;
		try (InputStream octetStream = octetStreamData.getOctetStream();) {
			relationshipsDocument = loadDocument(octetStream);
			octetStream.close();
		} catch (Exception e) {
			throw new TransformException(e.getMessage(), e);
		}
		try {
			toString(relationshipsDocument);
		} catch (TransformerException e) {
			throw new TransformException(e.getMessage(), e);
		}
		Element nsElement = relationshipsDocument.createElement("ns");
		nsElement.setAttributeNS(NAMESPACE_SPEC_NS, "xmlns:tns",
				"http://schemas.openxmlformats.org/package/2006/relationships");
		Element relationshipsElement = relationshipsDocument.getDocumentElement();
		NodeList childNodes = relationshipsElement.getChildNodes();
		for (int nodeIdx = 0; nodeIdx < childNodes.getLength(); nodeIdx++) {
			Node childNode = childNodes.item(nodeIdx);
			if (Node.ELEMENT_NODE != childNode.getNodeType()) {
				relationshipsElement.removeChild(childNode);
				nodeIdx--;
				continue;
			}
			Element childElement = (Element) childNode;
			String idAttribute = childElement.getAttribute("Id");
			if (!this.sourceIds.contains(idAttribute)) {
				relationshipsElement.removeChild(childNode);
				nodeIdx--;
			}
			/*
			 * See: ISO/IEC 29500-2:2008(E) - 13.2.4.24 Relationships Transform Algorithm.
			 */
			if (null == childElement.getAttributeNode("TargetMode")) {
				childElement.setAttribute("TargetMode", "Internal");
			}
		}

		sortRelationshipElements(relationshipsElement);
		try {
			return toOctetStreamData(relationshipsDocument);
		} catch (TransformerException e) {
			throw new TransformException(e.getMessage(), e);
		}
	}

	private static void sortRelationshipElements(Element relationshipsElement) {
		List<Element> relationshipElements = new LinkedList<>();
		NodeList relationshipNodes = relationshipsElement.getElementsByTagName("*");
		int nodeCount = relationshipNodes.getLength();
		for (int nodeIdx = 0; nodeIdx < nodeCount; nodeIdx++) {
			Node relationshipNode = relationshipNodes.item(0);
			Element relationshipElement = (Element) relationshipNode;
			relationshipElements.add(relationshipElement);
			relationshipsElement.removeChild(relationshipNode);
		}
		Collections.sort(relationshipElements, new RelationshipComparator());
		for (Element relationshipElement : relationshipElements) {
			relationshipsElement.appendChild(relationshipElement);
		}
	}

	private static String toString(Node dom) throws TransformerException {
		Source source = new DOMSource(dom);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		/*
		 * We have to omit the ?xml declaration if we want to embed the document.
		 */
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.transform(source, result);
		return stringWriter.getBuffer().toString();
	}

	private static OctetStreamData toOctetStreamData(Node node) throws TransformerException {
		Source source = new DOMSource(node);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		Result result = new StreamResult(outputStream);
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.transform(source, result);
		return new OctetStreamData(new ByteArrayInputStream(outputStream.toByteArray()));
	}

	private static Document loadDocument(InputStream documentInputStream)
			throws ParserConfigurationException, SAXException, IOException {
		InputSource inputSource = new InputSource(documentInputStream);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		return documentBuilderFactory.newDocumentBuilder().parse(inputSource);
	}

	/** {@inheritDoc} */
	@Override
	public Data transform(Data data, XMLCryptoContext context, OutputStream os) {
		return null;
	}

	/** {@inheritDoc} */
	@Override
	public boolean isFeatureSupported(String feature) {
		return false;
	}
}