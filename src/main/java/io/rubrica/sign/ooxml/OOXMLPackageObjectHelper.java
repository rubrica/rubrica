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

package io.rubrica.sign.ooxml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import io.rubrica.sign.ooxml.relprovider.RelationshipTransformParameterSpec;
import io.rubrica.sign.ooxml.relprovider.RelationshipTransformService;

final class OOXMLPackageObjectHelper {

	private static final String NAMESPACE_SPEC_NS = "http://www.w3.org/2000/xmlns/";
	private static final String DIGITAL_SIGNATURE_SCHEMA = "http://schemas.openxmlformats.org/package/2006/digital-signature";

	private static final String PACKAGE_REL_CONTENT_TYPE = "application/vnd.openxmlformats-package.relationships+xml";

	private static final String[] CONTENT_DIRS = new String[] { "word", "excel", //$NON-NLS-2$
			"xl", //$NON-NLS-1$
			"powerpoint" //$NON-NLS-1$
	};

	private static final Set<String> EXCLUDED_RELATIONSHIPS = new HashSet<>(6);
	static {
		EXCLUDED_RELATIONSHIPS
				.add("http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties");
		EXCLUDED_RELATIONSHIPS
				.add("http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties");
		EXCLUDED_RELATIONSHIPS
				.add("http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin");
		EXCLUDED_RELATIONSHIPS.add("http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail");
		EXCLUDED_RELATIONSHIPS.add("http://schemas.openxmlformats.org/officeDocument/2006/relationships/presProps");
		EXCLUDED_RELATIONSHIPS.add("http://schemas.openxmlformats.org/officeDocument/2006/relationships/viewProps");
	}

	private OOXMLPackageObjectHelper() {
		// No permitimos la instanciacion
	}

	static XMLObject getPackageObject(String nodeId, XMLSignatureFactory fac, byte[] ooXmlDocument, Document document,
			String signatureId) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException,
			ParserConfigurationException, SAXException {
		List<XMLStructure> objectContent = new LinkedList<>();
		objectContent.add(constructManifest(fac, ooXmlDocument));

		addSignatureTime(fac, document, signatureId, objectContent);

		return fac.newXMLObject(objectContent, nodeId, null, null);
	}

	private static boolean startsWithAnyOfThose(String in, String[] prefixes) {
		for (String prefix : prefixes) {
			if (in.startsWith(prefix)) {
				return true;
			}
		}
		return false;
	}

	private static boolean alreadyContains(List<Reference> references, Reference reference) {
		if (reference == null || references == null) {
			return true;
		}
		for (Reference r : references) {
			if (r.getURI().equals(reference.getURI())) {
				return true;
			}
		}
		return false;
	}

	private static void addParts(XMLSignatureFactory fac, ContentTypeManager contentTypeManager,
			List<Reference> references, byte[] ooXmlDocument, String[] applications, DigestMethod digestMethod)
			throws IOException {
		ZipInputStream zipInputStream = new ZipInputStream(new ByteArrayInputStream(ooXmlDocument));

		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (!startsWithAnyOfThose(zipEntry.getName(), applications)) {
				continue;
			}

			String contentType = contentTypeManager.getContentType(zipEntry.getName());

			// Solo se anade la referencia si existe contentType
			if (contentType != null) {
				Reference reference = fac.newReference("/" + zipEntry.getName() + "?ContentType=" + contentType,
						digestMethod);
				if (!alreadyContains(references, reference)) {
					references.add(reference);
				}
			}
		}
	}

	private static InputStream getContentTypesXMLInputStream(byte[] ooXmlDocument) throws IOException {
		ZipInputStream zipInputStream = new ZipInputStream(new ByteArrayInputStream(ooXmlDocument));
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if ("[Content_Types].xml".equals(zipEntry.getName())) {
				return zipInputStream;
			}
		}
		throw new IllegalStateException(
				"El documento OOXML es invalido ya que no contiene el fichero [Content_Types].xml");
	}

	private static Document loadDocumentNoClose(InputStream documentInputStream)
			throws ParserConfigurationException, SAXException, IOException {
		try (InputStream noCloseInputStream = new NoCloseInputStream(documentInputStream);) {
			InputSource inputSource = new InputSource(noCloseInputStream);
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
			DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
			return documentBuilder.parse(inputSource);
		}
	}

	private static void addRelationshipsReference(XMLSignatureFactory fac, String zipEntryName, Document relsDocument,
			List<Reference> manifestReferences, String contentType, DigestMethod digestMethod)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		RelationshipTransformParameterSpec parameterSpec = new RelationshipTransformParameterSpec();
		NodeList nodeList = relsDocument.getDocumentElement().getChildNodes();
		for (int nodeIdx = 0; nodeIdx < nodeList.getLength(); nodeIdx++) {
			Node node = nodeList.item(nodeIdx);
			if (node.getNodeType() != Node.ELEMENT_NODE) {
				continue;
			}
			Element element = (Element) node;
			String relationshipType = element.getAttribute("Type");
			// Obviamos ciertos tipos de relacion
			if (EXCLUDED_RELATIONSHIPS.contains(relationshipType)) {
				continue;
			}
			String relationshipId = element.getAttribute("Id");
			parameterSpec.addRelationshipReference(relationshipId);
		}

		List<Transform> transforms = new LinkedList<>();
		transforms.add(fac.newTransform(RelationshipTransformService.TRANSFORM_URI, parameterSpec));
		transforms.add(
				fac.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", (TransformParameterSpec) null));
		Reference reference = fac.newReference("/" + zipEntryName + "?ContentType=" + contentType, digestMethod,
				transforms, null, null);

		manifestReferences.add(reference);
	}

	private static void addRelationshipsReferences(XMLSignatureFactory fac, List<Reference> manifestReferences,
			byte[] ooXmlDocument, DigestMethod digestMethod) throws IOException, ParserConfigurationException,
			SAXException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		ZipInputStream zipInputStream = new ZipInputStream(new ByteArrayInputStream(ooXmlDocument));
		ZipEntry zipEntry;
		while (null != (zipEntry = zipInputStream.getNextEntry())) {
			if (!zipEntry.getName().endsWith(".rels")) {
				continue;
			}
			Document relsDocument = loadDocumentNoClose(zipInputStream);
			addRelationshipsReference(fac, zipEntry.getName(), relsDocument, manifestReferences,
					PACKAGE_REL_CONTENT_TYPE, digestMethod);
		}
	}

	private static Manifest constructManifest(XMLSignatureFactory fac, byte[] ooXmlDocument)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException,
			ParserConfigurationException, SAXException {
		DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA256, null);

		List<Reference> manifestReferences = new LinkedList<>();
		addRelationshipsReferences(fac, manifestReferences, ooXmlDocument, digestMethod);

		// Se obtiene el inputstream del fichero [Content_Types].xml para
		// inicializar el ContentTypeManager
		try (InputStream contentXml = getContentTypesXMLInputStream(ooXmlDocument);) {
			ContentTypeManager contentTypeManager = new ContentTypeManager(contentXml);
			addParts(fac, contentTypeManager, manifestReferences, ooXmlDocument, CONTENT_DIRS, digestMethod);
		}
		return fac.newManifest(manifestReferences);
	}

	private static void addSignatureTime(XMLSignatureFactory fac, Document document, String signatureId,
			List<XMLStructure> objectContent) {
		// SignatureTime
		Element signatureTimeElement = document.createElementNS(DIGITAL_SIGNATURE_SCHEMA, "mdssi:SignatureTime");
		signatureTimeElement.setAttributeNS(NAMESPACE_SPEC_NS, "xmlns:mdssi", DIGITAL_SIGNATURE_SCHEMA);
		Element formatElement = document.createElementNS(DIGITAL_SIGNATURE_SCHEMA, "mdssi:Format");
		formatElement.setTextContent("YYYY-MM-DDThh:mm:ssTZD");
		signatureTimeElement.appendChild(formatElement);
		Element valueElement = document.createElementNS(DIGITAL_SIGNATURE_SCHEMA, "mdssi:Value");
		valueElement.setTextContent(new SimpleDateFormat("yyyy-MM-dd'T'hh:mm:ss'Z'").format(new Date()));
		signatureTimeElement.appendChild(valueElement);

		List<XMLStructure> signatureTimeContent = new LinkedList<>();
		signatureTimeContent.add(new DOMStructure(signatureTimeElement));
		SignatureProperty signatureTimeSignatureProperty = fac.newSignatureProperty(signatureTimeContent,
				"#" + signatureId, "idSignatureTime");
		List<SignatureProperty> signaturePropertyContent = new LinkedList<>();
		signaturePropertyContent.add(signatureTimeSignatureProperty);
		SignatureProperties signatureProperties = fac.newSignatureProperties(signaturePropertyContent,
				"id-signature-time-" + UUID.randomUUID().toString());
		objectContent.add(signatureProperties);
	}
}