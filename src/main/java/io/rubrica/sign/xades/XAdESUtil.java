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

package io.rubrica.sign.xades;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.DocumentType;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.uji.crypto.xades.jxades.security.xml.XAdES.CommitmentTypeIdImpl;
import es.uji.crypto.xades.jxades.security.xml.XAdES.CommitmentTypeIndication;
import es.uji.crypto.xades.jxades.security.xml.XAdES.CommitmentTypeIndicationImpl;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES_EPES;
import io.rubrica.core.RubricaException;
import io.rubrica.sign.SignConstants;

/**
 * Utilidades varias para firmas XAdES.
 */
public final class XAdESUtil {

	private static final String[] SUPPORTED_XADES_NAMESPACE_URIS = new String[] { "http://uri.etsi.org/01903#",
			"http://uri.etsi.org/01903/v1.2.2#", "http://uri.etsi.org/01903/v1.3.2#",
			"http://uri.etsi.org/01903/v1.4.1#" };

	private static final Logger logger = Logger.getLogger(XAdESUtil.class.getName());

	/**
	 * Comprueba que los nodos de firma proporcionados sean firmas en formato XAdES.
	 * 
	 * @param signNodes
	 *            Listado de nodos de firma.
	 * @return {@code true} cuando todos los nodos sean firmas en este formato.
	 */
	static boolean checkSignNodes(List<Node> signNodes) {
		for (Node signNode : signNodes) {
			int lenCount = 0;
			for (final String xadesNamespace : SUPPORTED_XADES_NAMESPACE_URIS) {
				lenCount = lenCount + ((Element) signNode)
						.getElementsByTagNameNS(xadesNamespace, "QualifyingProperties").getLength();
			}
			if (lenCount == 0) {
				return false;
			}
		}
		return true;
	}

	static RubricaXMLAdvancedSignature getXmlAdvancedSignature(XAdES_EPES xades, String signedPropertiesTypeUrl,
			String digestMethodAlgorithm, String canonicalizationAlgorithm) throws RubricaException {
		RubricaXMLAdvancedSignature xmlSignature;
		try {
			xmlSignature = RubricaXMLAdvancedSignature.newInstance(xades);
		} catch (Exception e) {
			throw new RubricaException("No se ha podido instanciar la firma XML Avanzada de JXAdES: " + e, e);
		}

		// Establecemos el tipo de propiedades firmadas
		xmlSignature.setSignedPropertiesTypeUrl(signedPropertiesTypeUrl);

		try {
			xmlSignature.setDigestMethod(digestMethodAlgorithm);
		} catch (Exception e) {
			throw new RubricaException("No se ha podido establecer el algoritmo de huella digital: " + e, e);
		}

		xmlSignature.setCanonicalizationMethod(canonicalizationAlgorithm);

		return xmlSignature;
	}

	static Element getFirstElmentFromXPath(String xpathExpression, Element sourceElement) throws RubricaException {
		NodeList nodeList;
		try {
			nodeList = (NodeList) XPathFactory.newInstance().newXPath().evaluate(xpathExpression, sourceElement,
					XPathConstants.NODESET);
		} catch (XPathExpressionException e1) {
			throw new RubricaException(
					"No se ha podido evaluar la expresion indicada para la insercion de la firma Enveloped ('"
							+ xpathExpression + "'): " + e1,
					e1);
		}
		if (nodeList.getLength() < 1) {
			throw new RubricaException("La expresion indicada para la insercion de la firma Enveloped ('"
					+ xpathExpression + "') no ha devuelto ningun nodo");
		}
		if (nodeList.getLength() > 1) {
			logger.warning("La expresion indicada para la insercion de la firma Enveloped ('" + xpathExpression
					+ "') ha devuelto varios nodos, se usara el primero");
		}
		return (Element) nodeList.item(0);
	}

	/**
	 * Obtiene la lista de <i>CommitmentTypeIndication</i> declarados en el fichero
	 * de propiedades de par&aacute;metros adicionales.
	 * 
	 * @param xParams
	 *            Par&aacute;metros adicionales para la firma.
	 * @param signedDataId
	 *            Identificador del nodo a firmar (<i>Data Object</i>).
	 * @return Lista de <i>CommitmentTypeIndication</i> a incluir en la firma XAdES.
	 */
	public static List<CommitmentTypeIndication> parseCommitmentTypeIndications(Properties xParams,
			String signedDataId) {

		List<CommitmentTypeIndication> ret = new ArrayList<>();

		if (xParams == null) {
			return ret;
		}

		String tmpStr = xParams.getProperty(XAdESExtraParams.COMMITMENT_TYPE_INDICATIONS);

		if (tmpStr == null) {
			return ret;
		}

		int nCtis;
		try {
			nCtis = Integer.parseInt(tmpStr);
			if (nCtis < 1) {
				throw new NumberFormatException();
			}
		} catch (Exception e) {
			logger.severe(
					"El parametro adicional 'CommitmentTypeIndications' debe contener un valor numerico entero (el valor actual es "
							+ tmpStr + "), no se anadira el CommitmentTypeIndication: " + e);
			return ret;
		}

		String identifier;
		String description;
		ArrayList<String> documentationReferences;
		ArrayList<String> commitmentTypeQualifiers;

		for (int i = 0; i <= nCtis; i++) {
			// Identifier
			tmpStr = xParams.getProperty(XAdESExtraParams.COMMITMENT_TYPE_INDICATION_PREFIX + Integer.toString(i)
					+ XAdESExtraParams.COMMITMENT_TYPE_INDICATION_IDENTIFIER);
			if (tmpStr == null) {
				continue;
			}
			identifier = XAdESExtraParams.COMMITMENT_TYPE_IDENTIFIERS.get(tmpStr);
			if (identifier == null) {
				logger.severe("El identificador del CommitmentTypeIndication " + i + " no es un tipo soportado ("
						+ tmpStr + "), se omitira y se continuara con el siguiente");
				continue;
			}

			// Description
			description = xParams.getProperty(XAdESExtraParams.COMMITMENT_TYPE_INDICATION_PREFIX + Integer.toString(i)
					+ XAdESExtraParams.COMMITMENT_TYPE_INDICATION_DESCRIPTION);

			// DocumentationReferences
			tmpStr = xParams.getProperty(XAdESExtraParams.COMMITMENT_TYPE_INDICATION_PREFIX + Integer.toString(i)
					+ XAdESExtraParams.COMMITMENT_TYPE_INDICATION_DOCUMENTATION_REFERENCE);
			if (tmpStr == null) {
				documentationReferences = new ArrayList<>(0);
			} else {
				documentationReferences = new ArrayList<>();
				String[] docRefs = tmpStr.split(Pattern.quote("|"));
				for (String docRef : docRefs) {
					try {
						documentationReferences.add(new URL(docRef).toString());
					} catch (final MalformedURLException e) {
						logger.severe("La referencia documental '" + docRef + "' del CommitmentTypeIndication " + i
								+ " no es una URL, se omitira y se continuara con la siguiente referencia documental: "
								+ e);
						continue;
					}
				}
			}

			// CommitmentTypeQualifiers
			tmpStr = xParams.getProperty(XAdESExtraParams.COMMITMENT_TYPE_INDICATION_PREFIX + Integer.toString(i)
					+ XAdESExtraParams.COMMITMENT_TYPE_INDICATION_QUALIFIERS);
			if (tmpStr == null) {
				commitmentTypeQualifiers = new ArrayList<>(0);
			} else {
				commitmentTypeQualifiers = new ArrayList<>();
				String[] ctqs = tmpStr.split(Pattern.quote("|"));
				for (final String ctq : ctqs) {
					commitmentTypeQualifiers.add(ctq);
				}
			}

			ret.add(new CommitmentTypeIndicationImpl(new CommitmentTypeIdImpl(identifier.startsWith("urn:oid:") ? // OID
																													// como
																													// URN
																													// si
																													// el
																													// Id
																													// es
																													// OID,
																													// null
																													// en
																													// otro
																													// caso
					"OIDAsURN" : null, identifier, // Un OID o una URL
					description, // Descripcion textual (opcional)
					documentationReferences // Lista de URL (opcional)
			), signedDataId != null ? // Una URI, pero se acepta null
					"#" + signedDataId : //$NON-NLS-1$
					null, commitmentTypeQualifiers // Lista de elementos
													// textuales (opcional)
			));
		}
		return ret;
	}

	static String getDigestMethodByCommonName(String identifierHashAlgorithm) throws NoSuchAlgorithmException {
		String normalDigAlgo = SignConstants.getDigestAlgorithmName(identifierHashAlgorithm);
		if ("SHA1".equalsIgnoreCase(normalDigAlgo)) {
			return DigestMethod.SHA1;
		}
		if ("SHA-256".equalsIgnoreCase(normalDigAlgo)) {
			return DigestMethod.SHA256;
		}
		if ("SHA-512".equalsIgnoreCase(normalDigAlgo)) {
			return DigestMethod.SHA512;
		}
		throw new NoSuchAlgorithmException("No se soporta el algoritmo: " + normalDigAlgo);
	}

	static Element getRootElement(Document docSignature, Properties extraParams) {
		Properties xParams = extraParams != null ? extraParams : new Properties();
		String nodeName = xParams.getProperty(XAdESExtraParams.ROOT_XML_NODE_NAME, XAdESSigner.AFIRMA);
		String nodeNamespace = xParams.getProperty(XAdESExtraParams.ROOT_XML_NODE_NAMESPACE);
		String nodeNamespacePrefix = xParams.getProperty(XAdESExtraParams.ROOT_XML_NODE_NAMESPACE_PREFIX);

		Element afirmaRoot;
		if (nodeNamespace == null) {
			afirmaRoot = docSignature.createElement(nodeName);
		} else {
			afirmaRoot = docSignature.createElementNS(nodeNamespace, nodeName);
			if (nodeNamespacePrefix != null) {
				afirmaRoot.setAttribute(
						nodeNamespacePrefix.startsWith("xmlns:") ? nodeNamespacePrefix : "xmlns:" + nodeNamespacePrefix,
						nodeNamespace);
			}
		}
		afirmaRoot.setAttributeNS(null, FirmadorXAdES.ID_IDENTIFIER,
				nodeName + "-Root-" + UUID.randomUUID().toString());

		return afirmaRoot;
	}

	static List<Reference> createManifest(final List<Reference> referenceList, final XMLSignatureFactory fac,
			final RubricaXMLAdvancedSignature xmlSignature, final DigestMethod digestMethod,
			final Transform canonicalizationTransform, final String referenceId) {

		// Con Manifest vamos a incluir las referencias de "referencesList" en
		// el Manifest y luego
		// limpiar este mismo "referencesList" incluyendo posteriormente unica
		// referencia al propio
		// Manifest. Como es este "referencesList" lo que se firma, queda ya
		// listo con el Manifest
		// que contiene las referencias que de no usar Manifest estarian en
		// "referencesList".

		// Creamos un nodo padre donde insertar el Manifest
		final List<XMLStructure> objectContent = new LinkedList<>();

		final String manifestId = "Manifest-" + UUID.randomUUID().toString();
		objectContent.add(fac.newManifest(new ArrayList<>(referenceList), manifestId));

		final String manifestObjectId = "ManifestObject-" + UUID.nameUUIDFromBytes(referenceId.getBytes()).toString();
		xmlSignature.addXMLObject(fac.newXMLObject(objectContent, manifestObjectId, null, null));

		// Si usamos un manifest las referencias no van en la firma, sino en el
		// Manifest, y se
		// usa entonces en la firma una unica referencia a este Manifest
		referenceList.clear();
		referenceList.add(fac.newReference("#" + manifestId, digestMethod,
				canonicalizationTransform != null ? Collections.singletonList(canonicalizationTransform)
						: new ArrayList<Transform>(0),
				XAdESSigner.MANIFESTURI, "Manifest" + referenceId));

		return referenceList;
	}

	static Map<String, String> getOriginalXMLProperties(Document docum, String outputXmlEncoding) {
		Map<String, String> originalXMLProperties = new Hashtable<>();

		if (docum != null) {
			if (outputXmlEncoding != null) {
				originalXMLProperties.put(OutputKeys.ENCODING, outputXmlEncoding);
			} else if (docum.getXmlEncoding() != null) {
				originalXMLProperties.put(OutputKeys.ENCODING, docum.getXmlEncoding());
			}

			String tmpXmlProp = docum.getXmlVersion();
			if (tmpXmlProp != null) {
				originalXMLProperties.put(OutputKeys.VERSION, tmpXmlProp);
			}

			DocumentType dt = docum.getDoctype();
			if (dt != null) {
				tmpXmlProp = dt.getSystemId();
				if (tmpXmlProp != null) {
					originalXMLProperties.put(OutputKeys.DOCTYPE_SYSTEM, tmpXmlProp);
				}
			}
		}

		return originalXMLProperties;
	}
}