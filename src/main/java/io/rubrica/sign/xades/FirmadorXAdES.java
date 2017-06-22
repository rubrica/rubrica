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
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Logger;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import io.rubrica.core.RubricaException;
import io.rubrica.core.Util;
import io.rubrica.sign.XMLConstants;
import io.rubrica.util.MimeHelper;
import io.rubrica.xml.Utils;
import net.java.xades.security.xml.XAdES.CommitmentTypeIndication;
import net.java.xades.security.xml.XAdES.DataObjectFormat;
import net.java.xades.security.xml.XAdES.DataObjectFormatImpl;
import net.java.xades.security.xml.XAdES.ObjectIdentifierImpl;
import net.java.xades.security.xml.XAdES.XAdES;
import net.java.xades.security.xml.XAdES.XAdES_EPES;

/**
 * Firmador simple XAdES.
 */
public final class FirmadorXAdES {

	private static final String HTTP_PROTOCOL_PREFIX = "http://";
	private static final String HTTPS_PROTOCOL_PREFIX = "https://";

	private static final Logger logger = Logger.getLogger(FirmadorXAdES.class.getName());

	/** Identificador de identificadores en los nodos XML. */
	static final String ID_IDENTIFIER = "Id";

	private FirmadorXAdES() {
		// No permitimos la instanciacion
	}

	/**
	 * Firma datos en formato XAdES.
	 * <p>
	 * Este m&eacute;todo, al firmar un XML, firmas tambi&eacute;n sus hojas de
	 * estilo XSL asociadas, siguiendo el siguiente criterio:
	 * <ul>
	 * <li>Firmas XML <i>Enveloped</i>
	 * <ul>
	 * <li>Hoja de estilo con ruta relativa
	 * <ul>
	 * <li>No se firma.</li>
	 * </ul>
	 * </li>
	 * <li>Hola de estilo remota con ruta absoluta
	 * <ul>
	 * <li>Se restaura la declaraci&oacute;n de hoja de estilo tal y como estaba
	 * en el XML original</li>
	 * <li>Se firma una referencia (<i>canonicalizada</i>) a esta hoja
	 * remota</li>
	 * </ul>
	 * </li>
	 * <li>Hoja de estilo empotrada
	 * <ul>
	 * <li>Se restaura la declaraci&oacute;n de hoja de estilo tal y como estaba
	 * en el XML original</li>
	 * </ul>
	 * </li>
	 * </ul>
	 * </li>
	 * <li>Firmas XML <i>Externally Detached</i>
	 * <ul>
	 * <li>Hoja de estilo con ruta relativa
	 * <ul>
	 * <li>No se firma.</li>
	 * </ul>
	 * </li>
	 * <li>Hola de estilo remota con ruta absoluta
	 * <ul>
	 * <li>Se firma una referencia (<i>canonicalizada</i>) a esta hoja
	 * remota</li>
	 * </ul>
	 * </li>
	 * <li>Hoja de estilo empotrada
	 * <ul>
	 * <li>No es necesaria ninguna acci&oacute;n</li>
	 * </ul>
	 * </li>
	 * </ul>
	 * </li>
	 * <li>Firmas XML <i>Enveloping</i>
	 * <ul>
	 * <li>Hoja de estilo con ruta relativa
	 * <ul>
	 * <li>No se firma.</li>
	 * </ul>
	 * </li>
	 * <li>Hola de estilo remota con ruta absoluta
	 * <ul>
	 * <li>Se firma una referencia (<i>canonicalizada</i>) a esta hoja
	 * remota</li>
	 * </ul>
	 * </li>
	 * <li>Hoja de estilo empotrada
	 * <ul>
	 * <li>No es necesaria ninguna acci&oacute;n</li>
	 * </ul>
	 * </li>
	 * </ul>
	 * </li>
	 * <li>Firmas XML <i>Internally Detached</i>
	 * <ul>
	 * <li>Hoja de estilo con ruta relativa
	 * <ul>
	 * <li>No se firma.</li>
	 * </ul>
	 * </li>
	 * <li>Hola de estilo remota con ruta absoluta
	 * <ul>
	 * <li>Se firma una referencia (<i>canonicalizada</i>) a esta hoja
	 * remota</li>
	 * </ul>
	 * </li>
	 * <li>Hoja de estilo empotrada
	 * <ul>
	 * <li>No es necesaria ninguna acci&oacute;n</li>
	 * </ul>
	 * </li>
	 * </ul>
	 * </li>
	 * </ul>
	 * 
	 * @param data
	 *            Datos que deseamos firmar.
	 * @param algorithm
	 *            Algoritmo a usar para la firma.
	 *            <p>
	 *            Se aceptan los siguientes algoritmos en el par&aacute;metro
	 *            <code>algorithm</code>:
	 *            </p>
	 *            <ul>
	 *            <li>&nbsp;&nbsp;&nbsp;<i>SHA1withRSA</i></li>
	 *            <li>&nbsp;&nbsp;&nbsp;<i>SHA256withRSA</i></li>
	 *            <li>&nbsp;&nbsp;&nbsp;<i>SHA384withRSA</i></li>
	 *            <li>&nbsp;&nbsp;&nbsp;<i>SHA512withRSA</i></li>
	 *            </ul>
	 * @param certChain
	 *            Cadena de certificados del firmante
	 * @param pk
	 *            Clave privada del firmante
	 * @param xParams
	 *            Par&aacute;metros adicionales para la firma
	 *            (<a href="doc-files/extraparams.html">detalle</a>)
	 * @return Firma en formato XAdES
	 * @throws AOException
	 *             Cuando ocurre cualquier problema durante el proceso
	 */
	public static byte[] sign(byte[] data, String algorithm, PrivateKey pk, Certificate[] certChain, Properties xParams)
			throws RubricaException {

		String algoUri = XMLConstants.SIGN_ALGOS_URI.get(algorithm);

		if (algoUri == null) {
			throw new UnsupportedOperationException(
					"Los formatos de firma XML no soportan el algoritmo de firma '" + algorithm + "'");
		}

		// ***********************************************************************************************
		// ********** LECTURA PARAMETROS ADICIONALES
		// *****************************************************

		Properties extraParams = xParams != null ? xParams : new Properties();

		boolean avoidXpathExtraTransformsOnEnveloped = Boolean.parseBoolean(extraParams
				.getProperty(XAdESExtraParams.AVOID_XPATH_EXTRA_TRANSFORMS_ON_ENVELOPED, Boolean.FALSE.toString()));

		boolean onlySignningCert = Boolean.parseBoolean(
				extraParams.getProperty(XAdESExtraParams.INCLUDE_ONLY_SIGNNING_CERTIFICATE, Boolean.FALSE.toString()));

		String envelopedNodeXPath = extraParams
				.getProperty(XAdESExtraParams.INSERT_ENVELOPED_SIGNATURE_ON_NODE_BY_XPATH);

		String nodeToSign = extraParams.getProperty(XAdESExtraParams.NODE_TOSIGN);

		String digestMethodAlgorithm = extraParams.getProperty(XAdESExtraParams.REFERENCES_DIGEST_METHOD,
				XAdESSigner.DIGEST_METHOD);

		String canonicalizationAlgorithm = extraParams.getProperty(XAdESExtraParams.CANONICALIZATION_ALGORITHM,
				CanonicalizationMethod.INCLUSIVE);
		if ("none".equalsIgnoreCase(canonicalizationAlgorithm)) {
			canonicalizationAlgorithm = null;
		}

		String xadesNamespace = extraParams.getProperty(XAdESExtraParams.XADES_NAMESPACE, XAdESSigner.XADESNS);

		String signedPropertiesTypeUrl = extraParams.getProperty(XAdESExtraParams.SIGNED_PROPERTIES_TYPE_URL,
				XAdESSigner.XADES_SIGNED_PROPERTIES_TYPE);

		boolean ignoreStyleSheets = Boolean
				.parseBoolean(extraParams.getProperty(XAdESExtraParams.IGNORE_STYLE_SHEETS, Boolean.FALSE.toString()));

		boolean avoidBase64Transforms = Boolean.parseBoolean(
				extraParams.getProperty(XAdESExtraParams.AVOID_BASE64_TRANSFORMS, Boolean.FALSE.toString()));

		boolean headless = Boolean
				.parseBoolean(extraParams.getProperty(XAdESExtraParams.HEADLESS, Boolean.TRUE.toString()));

		boolean addKeyInfoKeyValue = Boolean.parseBoolean(
				extraParams.getProperty(XAdESExtraParams.ADD_KEY_INFO_KEY_VALUE, Boolean.TRUE.toString()));

		boolean addKeyInfoKeyName = Boolean.parseBoolean(
				extraParams.getProperty(XAdESExtraParams.ADD_KEY_INFO_KEY_NAME, Boolean.FALSE.toString()));

		boolean addKeyInfoX509IssuerSerial = Boolean.parseBoolean(
				extraParams.getProperty(XAdESExtraParams.ADD_KEY_INFO_X509_ISSUER_SERIAL, Boolean.FALSE.toString()));

		String precalculatedHashAlgorithm = extraParams.getProperty(XAdESExtraParams.PRECALCULATED_HASH_ALGORITHM);

		boolean facturaeSign = Boolean
				.parseBoolean(extraParams.getProperty(XAdESExtraParams.FACTURAE_SIGN, Boolean.FALSE.toString()));

		String outputXmlEncoding = extraParams.getProperty(XAdESExtraParams.OUTPUT_XML_ENCODING);

		String mimeType = extraParams.getProperty(XAdESExtraParams.XMLDSIG_OBJECT_MIME_TYPE);

		String encoding = extraParams.getProperty(XAdESExtraParams.XMLDSIG_OBJECT_ENCODING);

		// Dejamos que indiquen "base64" en vez de la URI, hacemos el cambio
		// manualmente
		if ("base64".equalsIgnoreCase(encoding)) {
			encoding = XMLConstants.BASE64_ENCODING;
		}

		// Comprobamos que sea una URI
		if (encoding != null && !encoding.isEmpty()) {
			try {
				new URI(encoding);
			} catch (final Exception e) {
				throw new RubricaException("La codificacion indicada en 'encoding' debe ser una URI: " + e, e);
			}
		}

		final boolean keepKeyInfoUnsigned = Boolean.parseBoolean(
				extraParams.getProperty(XAdESExtraParams.KEEP_KEYINFO_UNSIGNED, Boolean.FALSE.toString()));

		// ********** FIN LECTURA PARAMETROS ADICIONALES
		// *************************************************
		// ***********************************************************************************************

		URI uri = null;
		try {
			uri = extraParams.getProperty(XAdESExtraParams.URI) != null
					? Util.createURI(extraParams.getProperty(XAdESExtraParams.URI)) : null;
		} catch (final Exception e) {
			logger.warning("Se ha pasado una URI invalida como referencia a los datos a firmar: " + e);
		}

		// Utils.checkIllegalParams(format,
		// extraParams.getProperty(XAdESExtraParams.MODE,
		// SignConstants.SIGN_MODE_IMPLICIT), uri,
		// precalculatedHashAlgorithm, true);

		// Propiedades del documento XML original
		Map<String, String> originalXMLProperties = new Hashtable<>();

		// Factoria XML
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		// Elemento de datos
		Element dataElement;

		// Documento final de firma
		Document docSignature = null;

		String contentId = XAdESSigner.DETACHED_CONTENT_ELEMENT_NAME + "-" + UUID.randomUUID().toString();
		String styleId = XAdESSigner.DETACHED_STYLE_ELEMENT_NAME + "-" + UUID.randomUUID().toString();
		boolean avoidDetachedContentInclusion = false;

		// Elemento de estilo
		XmlStyle xmlStyle = new XmlStyle();

		// Nodo donde insertar la firma
		Element signatureInsertionNode = null;

		try {
			// Obtenemos el objeto XML
			Document docum = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(data));

			// Si no hay asignado un MimeType o es el por defecto
			// establecemos el de XML
			if (mimeType == null || XMLConstants.DEFAULT_MIMETYPE.equals(mimeType)) {
				mimeType = "text/xml";
			}

			// Obtenemos las propiedades del documento original
			originalXMLProperties = XAdESUtil.getOriginalXMLProperties(docum, outputXmlEncoding);
			dataElement = docum.getDocumentElement();
		}

		// Captura de error en caso de no ser un documento XML
		// **********************************************************
		// ********* Contenido no XML *******************************
		// **********************************************************
		catch (final Exception e) {
			throw new InvalidXMLException("Las firmas XAdES Enveloped solo pueden realizarse sobre datos XML", e);
		}

		// **********************************************************
		// ********* Fin contenido no XML ***************************
		// **********************************************************

		// ***************************************************
		// ***************************************************

		// La URI de contenido a firmar puede ser el nodo especifico si asi se
		// indico o el
		// nodo de contenido completo
		String tmpUri = "#" + contentId;
		String tmpStyleUri = "#" + styleId;

		try {
			docSignature = dbf.newDocumentBuilder().newDocument();
			docSignature.appendChild(docSignature.adoptNode(dataElement));
		} catch (Exception e) {
			throw new RubricaException("Error al crear la firma en formato Enveloped" + ": " + e, e);
		}

		List<Reference> referenceList = new ArrayList<>();
		XMLSignatureFactory fac = Utils.getDOMFactory();

		DigestMethod digestMethod;
		try {
			digestMethod = fac.newDigestMethod(digestMethodAlgorithm, null);
		} catch (Exception e) {
			throw new RubricaException("No se ha podido obtener un generador de huellas digitales para el algoritmo '"
					+ digestMethodAlgorithm + "'", e);
		}

		String referenceId = "Reference-" + UUID.randomUUID().toString();

		List<Transform> transformList = new ArrayList<>();

		// Primero anadimos las transformaciones a medida
		Utils.addCustomTransforms(transformList, extraParams, XAdESSigner.XML_SIGNATURE_PREFIX);

		Transform canonicalizationTransform;
		if (canonicalizationAlgorithm != null) {
			try {
				canonicalizationTransform = fac.newTransform(canonicalizationAlgorithm, (TransformParameterSpec) null);
			} catch (Exception e1) {
				throw new RubricaException("No se ha posido crear el canonizador para el algoritmo indicado ("
						+ canonicalizationAlgorithm + "): " + e1, e1);
			}
		} else {
			canonicalizationTransform = null;
		}

		if (canonicalizationTransform != null) {
			try {
				// Transformada para la canonicalizacion inclusiva
				transformList.add(canonicalizationTransform);
			} catch (Exception e) {
				throw new RubricaException("No se puede encontrar el algoritmo de canonicalizacion: " + e, e);
			}
		}

		// Crea una referencia indicando que se trata de una firma enveloped
		try {
			// Transformacion enveloped.
			// La enveloped siempre la primera, para que no se quede sin
			// nodos Signature por haber ejecutado antes otra transformacion
			transformList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));

			// Establecemos que es lo que se firma
			// 1.- Si se especifico un nodo, se firma ese nodo
			// 2.- Si el raiz tiene Id, se firma ese Id
			// 3.- Se firma todo el XML con ""
			// Tiene la raiz un Id?
			String ident = docSignature.getDocumentElement().getAttribute(ID_IDENTIFIER);
			if (ident != null && !ident.isEmpty()) {
				nodeToSign = ident;
			}

			// Salvo que sea una factura electronica o que se indique lo
			// contrario
			// se agrega una transformacion XPATH para eliminar el resto de
			// firmas del documento en las firmas Enveloped
			if (!facturaeSign && !avoidXpathExtraTransformsOnEnveloped) {
				transformList.add(fac.newTransform(Transform.XPATH,
						new XPathFilterParameterSpec(
								"not(ancestor-or-self::" + XAdESSigner.XML_SIGNATURE_PREFIX + ":Signature)", Collections
										.singletonMap(XAdESSigner.XML_SIGNATURE_PREFIX, XMLSignature.XMLNS))));
			}

			// Crea la referencia
			referenceList.add(fac.newReference(nodeToSign != null ? "#" + nodeToSign : "", digestMethod, transformList,
					XMLConstants.OBJURI, referenceId));
		} catch (Exception e) {
			throw new RubricaException("Error al generar la firma en formato enveloped: " + e, e);
		}

		// Nodo donde insertar la firma
		if (nodeToSign != null) {
			signatureInsertionNode = CustomUriDereferencer.getElementById(docSignature, nodeToSign);
		}

		// Instancia XADES_EPES
		XAdES_EPES xades = (XAdES_EPES) XAdES.newInstance(XAdES.EPES, // XAdES
				xadesNamespace, // XAdES NameSpace
				XAdESSigner.XADES_SIGNATURE_PREFIX, // XAdES Prefix
				XAdESSigner.XML_SIGNATURE_PREFIX, // XMLDSig Prefix
				digestMethodAlgorithm, // DigestMethod
				docSignature, // Document
				signatureInsertionNode != null ? // Nodo donde se inserta la
													// firma (como hijo), si no
													// se indica se usa la raiz
						signatureInsertionNode : docSignature.getDocumentElement());

		// SigningCertificate
		xades.setSigningCertificate((X509Certificate) certChain[0]);

		XAdESCommonMetadataUtil.addCommonMetadata(xades, extraParams);

		// DataObjectFormat
		String oid = extraParams.getProperty(XAdESExtraParams.CONTENT_TYPE_OID);

		if (oid == null && mimeType != null) {
			try {
				oid = MimeHelper.transformMimeTypeToOid(mimeType);
			} catch (final Exception e) {
				logger.warning("Error en la obtencion del OID del tipo de datos a partir del MimeType: " + e);
			}
			// Si no se reconoce el MimeType se habra establecido el por
			// defecto. Evitamos este comportamiento
			if (!MimeHelper.DEFAULT_MIMETYPE.equals(mimeType) && MimeHelper.DEFAULT_CONTENT_OID_DATA.equals(oid)) {
				oid = null;
			}
		}

		ObjectIdentifierImpl objectIdentifier = oid != null ? new ObjectIdentifierImpl("OIDAsURN",
				(oid.startsWith("urn:oid:") ? "" : "urn:oid:") + oid, null, new ArrayList<String>(0)) : null;

		ArrayList<DataObjectFormat> objectFormats = new ArrayList<>();
		DataObjectFormat objectFormat = new DataObjectFormatImpl(null, objectIdentifier,
				mimeType != null ? mimeType : XMLConstants.DEFAULT_MIMETYPE, encoding, "#" + referenceId);
		objectFormats.add(objectFormat);
		xades.setDataObjectFormats(objectFormats);

		// CommitmentTypeIndications:
		// -
		// http://www.w3.org/TR/XAdES/#Syntax_for_XAdES_The_CommitmentTypeIndication_element
		// - http://uri.etsi.org/01903/v1.2.2/ts_101903v010202p.pdf
		List<CommitmentTypeIndication> ctis = XAdESUtil.parseCommitmentTypeIndications(extraParams, referenceId);
		if (ctis != null && ctis.size() > 0) {
			xades.setCommitmentTypeIndications(ctis);
		}

		RubricaXMLAdvancedSignature xmlSignature = XAdESUtil.getXmlAdvancedSignature(xades, signedPropertiesTypeUrl,
				digestMethodAlgorithm,
				canonicalizationAlgorithm != null ? canonicalizationAlgorithm : CanonicalizationMethod.INCLUSIVE);

		// Genera la firma
		try {
			xmlSignature.sign(Arrays.asList(certChain), pk, algoUri, referenceList,
					"Signature-" + UUID.randomUUID().toString(), addKeyInfoKeyValue, addKeyInfoKeyName,
					addKeyInfoX509IssuerSerial, keepKeyInfoUnsigned);
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException(
					"Los formatos de firma XML no soportan el algoritmo de firma '" + algorithm + "':" + e, e);
		} catch (final Exception e) {
			throw new RubricaException("Error al generar la firma XAdES: " + e, e);
		}

		// Si no es enveloped quito los valores del estilo para que no se
		// inserte la
		// cabecera de hoja de estilo
		return Utils.writeXML(docSignature.getDocumentElement(), originalXMLProperties);
	}
}