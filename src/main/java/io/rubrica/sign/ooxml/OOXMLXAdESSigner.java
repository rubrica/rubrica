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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Logger;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;

import io.rubrica.sign.XMLConstants;
import io.rubrica.sign.xades.XAdESUtil;
import net.java.xades.security.xml.XAdES.CommitmentTypeIndication;
import net.java.xades.security.xml.XAdES.SignatureProductionPlace;
import net.java.xades.security.xml.XAdES.SignatureProductionPlaceImpl;
import net.java.xades.security.xml.XAdES.SignerRole;
import net.java.xades.security.xml.XAdES.SignerRoleImpl;
import net.java.xades.security.xml.XAdES.XAdES;
import net.java.xades.security.xml.XAdES.XAdES_EPES;
import net.java.xades.util.DOMOutputImpl;

/**
 * Firmador XAdES OOXML.
 */
class OOXMLXAdESSigner {

	private static final String ID_PACKAGE_OBJECT = "idPackageObject";
	private static final String ID_OFFICE_OBJECT = "idOfficeObject";

	/** URI que define la versi&oacute;n por defecto de XAdES. */
	private static final String XADESNS = "http://uri.etsi.org/01903/v1.3.2#";

	private static final String XADES_SIGNATURE_PREFIX = "xd";
	private static final String XML_SIGNATURE_PREFIX = "ds";

	private static final Logger logger = Logger.getLogger(OOXMLXAdESSigner.class.getName());

	private OOXMLXAdESSigner() {
		// No permitimos la instanciacion
	}

	/**
	 * Obtiene el XML de firma XAdES <i>enveloping</i> OOXML.
	 * 
	 * @param ooXmlDocument
	 *            Documento OOXML original.
	 * @param algorithm
	 *            Algoritmo de firma.
	 * @param pk
	 *            Clave privada para la firma.
	 * @param certChain
	 *            Cadena de certificados del firmante.
	 * @param xParams
	 *            Par&aacute;metros adicionales de la firma.
	 * @return XML de firma.
	 * @throws ParserConfigurationException
	 *             Si hay problemas con el analizador XML por defecto.
	 * @throws GeneralSecurityException
	 *             Si ocurre alg&uacute;n problema de seguridad.
	 * @throws SAXException
	 *             Si hay problemas en XML SAX.
	 * @throws IOException
	 *             Si hay problemas gen&eacute;ricos en el tratamiento de datos.
	 * @throws XMLSignatureException
	 *             Si hay problemas con la firma XML.
	 * @throws MarshalException
	 *             Si hay problemas con la envoltura de la firma XML.
	 */
	static byte[] getSignedXML(byte[] ooXmlDocument, String algorithm, PrivateKey pk, X509Certificate[] certChain,
			Properties xParams) throws ParserConfigurationException, GeneralSecurityException, IOException,
			SAXException, MarshalException, XMLSignatureException {

		String algoUri = XMLConstants.SIGN_ALGOS_URI.get(algorithm);
		if (algoUri == null) {
			throw new UnsupportedOperationException(
					"Los formatos de firma XML no soportan el algoritmo de firma '" + algorithm + "'");
		}

		Properties extraParams = xParams != null ? xParams : new Properties();

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document docSignature = dbf.newDocumentBuilder().newDocument();

		// Instancia XADES_EPES
		XAdES_EPES xades = (XAdES_EPES) XAdES.newInstance(XAdES.EPES, // XAdES-EPES
				XADESNS, // XAdES NameSpace
				XADES_SIGNATURE_PREFIX, // XAdES Prefix
				XML_SIGNATURE_PREFIX, // XMLDSig Prefix
				DigestMethod.SHA512, // DigestMethod
				docSignature, // Document
				docSignature.getDocumentElement() // Element
		);

		// *******************************************************************
		// ************* ATRIBUTOS XAdES *************************************

		// SigningCertificate
		xades.setSigningCertificate(certChain[0]);

		// SignatureProductionPlace
		final SignatureProductionPlace spp = getSignatureProductionPlace(
				extraParams.getProperty(OOXMLExtraParams.SIGNATURE_PRODUCTION_CITY),
				extraParams.getProperty(OOXMLExtraParams.SIGNATURE_PRODUCTION_PROVINCE),
				extraParams.getProperty(OOXMLExtraParams.SIGNATURE_PRODUCTION_POSTAL_CODE),
				extraParams.getProperty(OOXMLExtraParams.SIGNATURE_PRODUCTION_COUNTRY));

		if (spp != null) {
			xades.setSignatureProductionPlace(spp);
		}

		// CommitmentTypeIndications:
		// -
		// http://www.w3.org/TR/XAdES/#Syntax_for_XAdES_The_CommitmentTypeIndication_element
		// - http://uri.etsi.org/01903/v1.2.2/ts_101903v010202p.pdf
		List<CommitmentTypeIndication> ctis = XAdESUtil.parseCommitmentTypeIndications(extraParams, null);
		if (ctis != null && ctis.size() > 0) {
			xades.setCommitmentTypeIndications(ctis);
		}

		// SignerRole
		String signerRoleValue = extraParams.getProperty(OOXMLExtraParams.SIGNER_CLAIMED_ROLES);
		if (signerRoleValue != null) {
			SignerRole signerRole = new SignerRoleImpl();
			signerRole.addClaimedRole(signerRoleValue);
			xades.setSignerRole(signerRole);
		}

		// SigningTime
		xades.setSigningTime(new Date());

		// ************* FIN ATRIBUTOS XAdES *********************************
		// *******************************************************************

		// Creamos el objeto final de firma
		OOXMLAdvancedSignature xmlSignature = OOXMLAdvancedSignature.newInstance(xades, ooXmlDocument);

		// Lista de referencias a firmar
		List<Reference> referenceList = new ArrayList<>();

		// Identificador de primer nivel de la firma
		String signatureId = "xmldsig-" + UUID.randomUUID().toString();

		// Creamos la factoria de firma XML
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

		// Huella digital para las referencias
		DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA512, null);

		// Anadimos los nodos especificos OOXML y las referencias a ellos

		// idPackageObject
		xmlSignature.addXMLObject(OOXMLPackageObjectHelper.getPackageObject(ID_PACKAGE_OBJECT, fac, ooXmlDocument,
				docSignature, signatureId));
		referenceList.add(fac.newReference("#" + ID_PACKAGE_OBJECT, digestMethod, null,
				"http://www.w3.org/2000/09/xmldsig#Object", null));

		// idOfficeObject
		xmlSignature.addXMLObject(OOXMLOfficeObjectHelper.getOfficeObject(ID_OFFICE_OBJECT, fac, docSignature,
				signatureId, extraParams.getProperty(OOXMLExtraParams.SIGNATURE_COMMENTS),
				extraParams.getProperty(OOXMLExtraParams.SIGNATURE_ADDRESS1),
				extraParams.getProperty(OOXMLExtraParams.SIGNATURE_ADDRESS2),
				ctis != null && ctis.size() > 0 ? "1" : null));
		referenceList.add(fac.newReference("#" + ID_OFFICE_OBJECT, digestMethod, null,
				"http://www.w3.org/2000/09/xmldsig#Object", null));

		xmlSignature.sign(certChain, pk, XMLConstants.SIGN_ALGOS_URI.get(algorithm), referenceList, signatureId);

		return writeXML(docSignature.getDocumentElement());
	}

	/**
	 * Escribe un XML como texto.
	 * 
	 * @param node
	 *            Nodo XML que queremos pasar a texto
	 * @return Cadena de texto con el XML en forma de array de octetos
	 */
	private static byte[] writeXML(Node node) {
		// La codificacion por defecto sera UTF-8
		String xmlEncoding = "UTF-8";

		// Primero creamos un writer
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Writer writer = null;
		try {
			writer = new OutputStreamWriter(baos, xmlEncoding);
		} catch (final UnsupportedEncodingException e) {
			logger.warning("La codificacion '" + xmlEncoding + "' no es valida, se usara la por defecto: " + e);
			writer = new OutputStreamWriter(baos);
		}

		// Ahora escribimos el XML usando XALAN
		writeXMLwithXALAN(writer, node, xmlEncoding);

		try {
			DocumentBuilderFactory.newInstance().newDocumentBuilder()
					.parse(new ByteArrayInputStream(baos.toByteArray()));
		} catch (Exception e) {
			logger.severe(
					"No se ha podido recargar el XML para insertar los atributos de la cabecera, quizas la codificacion se vea afectada: "
							+ e);
			return baos.toByteArray();
		}

		// Y devolvemos el resultado como array de bytes, insertando antes la
		// cabecera de hoja de estilo
		try {
			return new String(baos.toByteArray(), xmlEncoding).getBytes(xmlEncoding);
		} catch (Exception e) {
			logger.warning(
					"La codificacion '" + xmlEncoding + "' no es valida, se usara la por defecto del sistema: " + e);
			return new String(baos.toByteArray()).getBytes();
		}
	}

	private static void writeXMLwithXALAN(Writer writer, Node node, String xmlEncoding) {
		LSSerializer serializer = ((DOMImplementationLS) node.getOwnerDocument().getImplementation())
				.createLSSerializer();
		serializer.getDomConfig().setParameter("namespaces", Boolean.FALSE);
		DOMOutputImpl output = new DOMOutputImpl();
		output.setCharacterStream(writer);
		if (xmlEncoding != null) {
			output.setEncoding(xmlEncoding);
		}
		serializer.write(node, output);
	}

	private static SignatureProductionPlace getSignatureProductionPlace(String city, String province, String postalCode,
			String country) {
		if (city == null && province == null && postalCode == null && country == null) {
			return null;
		}
		return new SignatureProductionPlaceImpl(city, province, postalCode, country);
	}
}