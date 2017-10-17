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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Logger;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.uji.crypto.xades.jxades.util.Base64;
import es.uji.crypto.xades.jxades.util.XMLUtils;
import io.rubrica.core.RubricaException;
import io.rubrica.sign.InvalidFormatException;
import io.rubrica.sign.SignInfo;
import io.rubrica.sign.Signer;
import io.rubrica.sign.XMLConstants;
import io.rubrica.xml.Utils;

/**
 * Manejador de firmas XML XAdES
 * <p>
 * Soporta XAdES-BES y XAdES-EPES.
 * </p>
 * <p>
 * Debido a errores en algunas versiones del entorno de ejecuci&oacute;n de
 * Java, esta clase puede generar ocasionalmente mensajes en consola del tipo:
 * <code>[Fatal Error] :1:1: Content is not allowed in prolog.</code>. Estos
 * deben ignorarse, ya que no indican ninguna condici&oacute;n de error ni
 * malfuncionamiento.
 * </p>
 * <p>
 * Los atributos espec&iacute;ficos XAdES implementados por esta clase
 * (adem&aacute;s de los relativos a las politicas de firma) son:
 * </p>
 * <ul>
 * <li><i>SigningTime</i></li>
 * <li><i>SigningCerticate</i></li>
 * <li><i>IssuerSerial</i></li>
 * <li><i>SignedDataObjectProperties</i></li>
 * </ul>
 * <p>
 * <b>Distintos formatos de firmas XML</b>
 * </p>
 * <dl>
 * <dt><i>Detached</i></dt>
 * <dd>
 * <p>
 * La firma XML en modo <i>Detached</i> permite tener una firma de forma
 * separada e independiente del contenido firmado, pudiendo relacionar firma con
 * contenido firmado mediante una referencia de tipo URI. Este tipo de firmas es
 * &uacute;til cuando no se puede modificar el contenido original pero se desea
 * constatar su autenticidad, procedencia, etc.<br>
 * </p>
 * <p>
 * Un uso com&uacute;n de este formato es en la descarga de ficheros, pudiendo
 * poner a disposici&oacute;n del internauta, junto al contenido a descargar, un
 * peque&ntilde;o fichero de firma para verificar la integridad del primero.
 * </p>
 * <p>
 * Un ejemplo de este tipo de firmas ser&iacute;a la siguiente estructura
 * (resumida) XML:
 * </p>
 *
 * <pre>
 *   &lt;?xml version="1.0" encoding="UTF-8"?&gt;
 *    &lt;ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"&gt;
 *     &lt;ds:SignedInfo&gt;
 *      &lt;ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/&gt;
 *      &lt;ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/&gt;
 *      &lt;ds:Reference URI="http://www.mpt.es/contenido"&gt;
 *       &lt;ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/&gt;
 *       &lt;ds:DigestValue/&gt;
 *      &lt;/ds:Reference&gt;
 *     &lt;/ds:SignedInfo&gt;
 *     &lt;ds:SignatureValue/&gt;
 *    &lt;/ds:Signature&gt;
 * </pre>
 * <p>
 * En este ejemplo, los datos firmados se encuentran en un servidor Web
 * accesible p&uacute;blicamente: <cite>http://www.mpt.es/contenido</cite>, y se
 * referencia como tal, conformando lo que se denomina <i>Externally
 * Detached</i> o "Detached Externa".
 * </p>
 * <p>
 * Cuando se desea firmar un contenido con un formato <i>Detached</i>, pero se
 * quiere eliminar la dependencia de la disponibilidad externa del contenido
 * firmado, es posible crear una estructura XML que contenga los propios
 * contenidos y la firma, pero cada uno en una subestructura independiente,
 * manteniendo asi el concepto de <i>Detached</i> (firma y contenido firmado no
 * se interrelacionan directamente). Para adecuarse al est&aacute;ndar los nodos
 * de firma y contenido debe encontrarse en el mismo nivel dentro del XML.
 * </p>
 * <p>
 * Un ejemplo de esta estructura XML ser&iacute;a:
 * </p>
 *
 * <pre>
 *    &lt;?xml version="1.0" encoding="UTF-8"?&gt;
 *    &lt;internally-detached&gt;
 *     &lt;ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"&gt;
 *      &lt;ds:SignedInfo&gt;
 *       &lt;ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/&gt;
 *       &lt;ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/&gt;
 *       &lt;ds:Reference URI="#data"&gt;
 *         &lt;ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/&gt;
 *         &lt;ds:DigestValue/&gt;
 *       &lt;/ds:Reference&gt;
 *      &lt;/ds:SignedInfo&gt;
 *      &lt;ds:SignatureValue/&gt;
 *     &lt;/ds:Signature&gt;
 *     &lt;document Id="data"&gt;
 *      &lt;title&gt;title&lt;/title&gt;
 *      &lt;author&gt;writer&lt;/author&gt;
 *      &lt;date&gt;today&lt;/date&gt;
 *      &lt;content&gt;
 *       &lt;para&gt;First paragraph&lt;/para&gt;
 *       &lt;para&gt;Second paragraph&lt;/para&gt;
 *      &lt;/content&gt;
 *     &lt;/document&gt;
 *    &lt;/internally-detached&gt;
 * </pre>
 * <p>
 * En este caso, la estructura <i>internally-detached</i> contiene dos
 * subestructuras, la firma (<i>Signature</i>) y el propio contenido firmado
 * (<i>document</i>). La forma de relacionar ambos es, como ocurr&iacute;a en el
 * primer ejemplo, con una URI, solo que en este caso es interna al documento
 * XML, referenciando el identificador de la subestructura del contenido firmado
 * (<i>data</i>).
 * </p>
 * <p>
 * A esta variante de firma <i>Detached</i> se la conoce como <i>Internally
 * Detached</i>, o "Detached Interna".
 * </p>
 * <p>
 * Para unificar las superestructuras creadas dentro de un formato "Detached
 * Interno", el Cliente @firma construye siempre el siguiente esqueleto XML:
 * </p>
 *
 * <pre>
 *    &lt;CONTENT Id="id" Encoding="codificacion" MimeType="MimeType" Algorithm=""&gt;
 *     &lt;!  CONTENIDO FIRMADO --&gt;
 *    &lt;/CONTENT&gt;
 * </pre>
 * <p>
 * Es decir, el contenido a firmar, ya sea XML o no-XML, se encapsula dentro de
 * una etiqueta XML llamada CONTENT, en la que se indica la codificaci&oacute;n
 * del contenido (UTF-8, Base64, etc.), el tipo de contenido (imagen JPEG,
 * texto, XML, etc.) y el algoritmo utilizado para calcular la huella digital de
 * este (por ejemplo, SHA-1).
 * </p>
 * <p>
 * Como la superestructura es XML, si el contenido tambi&eacute;n es XML la
 * inserci&oacute;n es directa (como en el primer ejemplo de "Detached Interna",
 * pero si no es XML se codifica en Base64 antes de insertarse, resultando una
 * estructura con una forma similar a la siguiente:
 * </p>
 *
 * <pre>
 *    &lt;CONTENT Id="id" Encoding="Base64" MimeType="application/octect-stream" Algorithm=""&gt;
 *     SFGJKASGFJKASEGUYFGEYGEYRGADFJKASGDFSUYFGAUYEGWEYJGDFYKGYKGWJKEGYFWYJ=
 *    &lt;/CONTENT&gt;
 * </pre>
 * <p>
 * La larga cadena de caracteres ser&iacute;a una codificaci&oacute;n Base64 del
 * original interpretado en su forma binaria pura.
 * </p>
 * </dd>
 * <dt><i>Enveloping</i></dt>
 * <dd>
 * <p>
 * Otra variante de firma es la <i>Enveloping</i>, en la que la estructura XML
 * de firma es la &uacute;nica en el documento de firma, y esta contiene
 * internamente el contenido firmado (en un nodo propio).
 * </p>
 *
 * <pre>
 *    &lt;?xml version="1.0" encoding="UTF-8"?&gt;
 *    &lt;ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"&gt;
 *     &lt;ds:SignedInfo&gt;
 *      &lt;ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/&gt;
 *      &lt;ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/&gt;
 *      &lt;ds:Reference URI="#obj"&gt;
 *       &lt;ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/&gt;
 *       &lt;ds:DigestValue/&gt;
 *      &lt;/ds:Reference&gt;
 *     &lt;/ds:SignedInfo&gt;
 *     &lt;ds:SignatureValue/&gt;
 *     &lt;ds:Object Id="obj"&gt;SFGJKASGFJKASEGUYFGEYGEYRGADFJKASGDFSUYFG=&lt;/ds:Object&gt;
 *    &lt;/ds:Signature&gt;
 * </pre>
 * <p>
 * En este caso, los datos firmados se encuentran en el nodo <i>Object</i>,
 * referenciados internamente al XML mediante el identificador <i>obj</i>.
 * </p>
 * <p>
 * Al igual que ocurr&iacute;a con el formato <i>Detached</i>, si los datos no
 * son XML, no es posible insertarlos directamente dentro de una estructura XML,
 * por lo que se codifican previamente en Base64.
 * </p>
 * </dd>
 * <dt><i>Enveloped</i></dt>
 * <dd>
 * <p>
 * Este formato de firma XMLDSig est&aacute; pensado para que un contenido XML
 * pueda auto-contener su propia firma digital, insert&aacute;ndola en un nodo
 * propio interno, por lo que, al contrario que en los formatos anteriores, no
 * es posible firmar contenido que no sea XML.
 * </p>
 * <p>
 * Un ejemplo simple del resultado de una firma <i>Enveloped</i> podr&iacute;a
 * ser el siguiente:
 * </p>
 *
 * <pre>
 *    &lt;!DOCTYPE Enveloped [
 *     &lt;!ENTITY ds "http://www.w3.org/2000/09/xmldsig#"&gt;
 *     &lt;!ENTITY c14n "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"&gt;
 *     &lt;!ENTITY enveloped "http://www.w3.org/2000/09/xmldsig#enveloped-signature"&gt;
 *     &lt;!ENTITY xslt "http://www.w3.org/TR/1999/REC-xslt-19991116"&gt;
 *     &lt;!ENTITY digest "http://www.w3.org/2000/09/xmldsig#sha1"&gt;
 *    ]&gt;
 *    &lt;Letter&gt;
 *     &lt;Return-address&gt;address&lt;/Return-address&gt;
 *     &lt;To&gt;You&lt;/To&gt;
 *     &lt;Message&gt;msg body&lt;/Message&gt;
 *     &lt;From&gt;
 *      &lt;ds:Signature xmlns:ds="ds"&gt;
 *       &lt;ds:SignedInfo&gt;
 *        &lt;ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/&gt;
 *        &lt;ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/&gt;
 *        &lt;ds:Reference URI=""&gt;
 *         &lt;ds:Transforms&gt;
 *          &lt;ds:Transform Algorithm="enveloped"&gt;&lt;/ds:Transform&gt;
 *         &lt;/ds:Transforms&gt;
 *         &lt;ds:DigestMethod Algorithm="digest"/&gt;
 *         &lt;ds:DigestValue&gt;&lt;/ds:DigestValue&gt;
 *        &lt;/ds:Reference&gt;
 *       &lt;/ds:SignedInfo&gt;
 *       &lt;ds:SignatureValue/&gt;
 *      &lt;/ds:Signature&gt;
 *     &lt;/From&gt;
 *     &lt;Attach&gt;attachement&lt;/Attach&gt;
 *    &lt;/Letter&gt;
 * </pre>
 * <p>
 * En este caso, el documento original (<i>Letter</i>), contiene internamente la
 * estructura de firma digital (<i>Signature</i>).
 * </p>
 * <p>
 * Una peculiaridad de la estructura generada es que esta referenciada mediante
 * una URI vac&iacute;a (<code>URI=""</code>), lo cual indica que la firma
 * aplica a la totalidad del documento original.
 * </p>
 * </dd>
 * </dl>
 */
public final class XAdESSigner implements Signer {

	private static final Logger logger = Logger.getLogger(XAdESSigner.class.getName());

	private static final String ID_IDENTIFIER = "Id";

	/** Etiqueta de los nodos firma de los XML firmados. */
	public static final String SIGNATURE_TAG = "Signature";

	/** URI que define la versi&oacute;n por defecto de XAdES. */
	static final String XADESNS = "http://uri.etsi.org/01903/v1.3.2#";

	/** URI que define el tipo de propiedades firmadas de XAdES (1.4.x). */
	static final String XADES_SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties";

	/** URI que define una referencia de tipo MANIFEST. */
	static final String MANIFESTURI = "http://www.w3.org/2000/09/xmldsig#Manifest";

	static final String AFIRMA = "AFIRMA";
	static final String XML_SIGNATURE_PREFIX = "ds";
	static final String XADES_SIGNATURE_PREFIX = "xades";
	static final String SIGNATURE_NODE_NAME = XML_SIGNATURE_PREFIX + ":Signature";
	static final String DETACHED_CONTENT_ELEMENT_NAME = "CONTENT";
	static final String DETACHED_STYLE_ELEMENT_NAME = "STYLE";

	/** Algoritmo de huella digital por defecto para las referencias XML. */
	static final String DIGEST_METHOD = DigestMethod.SHA512;

	static final String STYLE_REFERENCE_PREFIX = "StyleReference-";

	static final String XMLDSIG_ATTR_MIMETYPE_STR = "MimeType";
	static final String XMLDSIG_ATTR_ENCODING_STR = "Encoding";

	static {
		Utils.installXmlDSigProvider();
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
	 * @param key
	 *            Clave privada a usar para firmar.
	 * @param certChain
	 *            Cadena de certificados del cliente
	 * @param xParams
	 *            Par&aacute;metros adicionales para la firma
	 *            (<a href="doc-files/extraparams.html">detalle</a>)
	 * @return Firma en formato XAdES
	 * @throws AOException
	 *             Cuando ocurre cualquier problema durante el proceso
	 */
	@Override
	public byte[] sign(final byte[] data, final String algorithm, final PrivateKey key, final Certificate[] certChain,
			final Properties xParams) throws RubricaException {

		return FirmadorXAdES.sign(data, algorithm, key, certChain, xParams);
	}

	/**
	 * Comprueba si la firma es <i>detached</i>. Previamente debe haberse
	 * comprobado que el XML se corresponde con una firma XAdES.
	 * 
	 * @param element
	 *            Elemento que contiene el nodo ra&iacute;z del documento que se
	 *            quiere comprobar
	 * @return <code>true</code> si la firma es <i>detached</i>,
	 *         <code>false</code> en caso contrario.
	 */
	public static boolean isDetached(final Element element) {
		if (element == null) {
			return false;
		}

		try {
			String dataNodeId = null;
			final NodeList mainChildNodes = element.getChildNodes();
			for (int i = 0; i < mainChildNodes.getLength(); i++) {
				if (!mainChildNodes.item(i).getNodeName().equals(SIGNATURE_TAG)) {
					dataNodeId = ((Element) mainChildNodes.item(i)).getAttribute(ID_IDENTIFIER);
					break;
				}
			}
			if (dataNodeId == null || dataNodeId.length() == 0) {
				return false;
			}

			final NodeList transformList = element.getElementsByTagNameNS(XMLConstants.DSIGNNS, "Reference");
			for (int i = 0; i < transformList.getLength(); i++) {
				if (((Element) transformList.item(i)).getAttribute("URI").equals('#' + dataNodeId)) {
					return true;
				}
			}
		} catch (final Exception e) {
			return false;
		}

		return false;
	}

	/**
	 * Comprueba si la firma es <i>enveloped</i>. Previamente debe haberse
	 * comprabado que el XML se corresponde con una firma XAdES.
	 * 
	 * @param element
	 *            Elemento que contiene el nodo ra&iacute;z del documento que se
	 *            quiere comprobar
	 * @return <code>true</code> cuando la firma es <i>enveloped</i>,
	 *         <code>false</code> en caso contrario.
	 */
	public static boolean isEnveloped(final Element element) {
		final NodeList transformList = element.getElementsByTagNameNS(XMLConstants.DSIGNNS, "Transform");
		for (int i = 0; i < transformList.getLength(); i++) {
			if (((Element) transformList.item(i)).getAttribute("Algorithm").equals(Transform.ENVELOPED)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Comprueba si la firma es <i>enveloping</i>. Previamente debe haberse
	 * comprabado que el XML se corresponde con una firma XAdES.
	 * 
	 * @param element
	 *            Elemento que contiene el nodo ra&iacute;z del documento que se
	 *            quiere comprobar.
	 * @return <code>true</code> cuando la firma es <i>enveloping</i>,
	 *         <code>false</code> en caso contrario.
	 */
	public static boolean isEnveloping(final Element element) {
		if (element.getLocalName().equals(SIGNATURE_TAG) || element.getLocalName().equals(AFIRMA)
				&& element.getFirstChild().getLocalName().equals(SIGNATURE_TAG)) {
			return true;
		}
		return false;
	}

	public byte[] getData(final byte[] sign) throws InvalidFormatException {
		// nueva instancia de DocumentBuilderFactory que permita espacio de
		// nombres (necesario para XML)
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		Element rootSig;
		Element elementRes = null;

		try {
			// comprueba que sea una documento de firma valido
			if (!isSign(sign)) {
				throw new InvalidFormatException("El documento no es un documento de firmas valido.");
			}

			// obtiene la raiz del documento de firmas
			rootSig = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(sign)).getDocumentElement();

			// si es detached
			if (XAdESSigner.isDetached(rootSig)) {
				Element firstChild = (Element) rootSig.getFirstChild();
				// si el documento es un xml se extrae como tal
				if (firstChild.getAttribute(XMLDSIG_ATTR_MIMETYPE_STR).equals("text/xml")) {
					elementRes = (Element) firstChild.getFirstChild();
				}
				// si el documento es binario se deshace la codificacion en
				// Base64 si y solo si esta declarada esta transformacion
				else {
					// TODO: Deshacer solo el Base64 si existe la transformacion
					// Base64 (COMPROBAR)
					return isBase64TransformationDeclared(rootSig, firstChild.getAttribute(ID_IDENTIFIER))
							? Base64.decode(firstChild.getTextContent()) : firstChild.getTextContent().getBytes();
				}
			}

			// Si es enveloped
			else if (XAdESSigner.isEnveloped(rootSig)) {
				removeEnvelopedSignatures(rootSig);
				elementRes = rootSig;
			}

			// Si es enveloping
			else if (XAdESSigner.isEnveloping(rootSig)) {
				// Obtiene el nodo Object de la primera firma
				Element object = (Element) rootSig.getElementsByTagNameNS(XMLConstants.DSIGNNS, "Object").item(0);
				// Si el documento es un xml se extrae como tal
				if (object.getAttribute(XMLDSIG_ATTR_MIMETYPE_STR).equals("text/xml")) {
					elementRes = (Element) object.getFirstChild();
				}
				// Si el documento es binario se deshace la codificacion en
				// Base64 si y solo si esta declarada esta transformacion
				else {
					// TODO: Deshacer solo el Base64 si existe la transformacion
					// Base64 (COMPROBAR)
					return isBase64TransformationDeclared(rootSig, object.getAttribute(ID_IDENTIFIER))
							? Base64.decode(object.getTextContent()) : object.getTextContent().getBytes();
				}
			}
		} catch (Exception ex) {
			throw new InvalidFormatException("Error al leer el fichero de firmas: " + ex, ex);
		}

		// si no se ha recuperado ningun dato se devuelve null
		if (elementRes == null) {
			return null;
		}

		// convierte el documento obtenido en un array de bytes
		ByteArrayOutputStream baosSig = new ByteArrayOutputStream();
		XMLUtils.writeXML(baosSig, elementRes, false);

		return baosSig.toByteArray();
	}

	private void removeEnvelopedSignatures(Element rootSig) {
		// obtiene las firmas y las elimina
		NodeList mainChildNodes = rootSig.getChildNodes();
		for (int i = 0; i < mainChildNodes.getLength(); i++) {
			if (mainChildNodes.item(i).getNodeType() == Node.ELEMENT_NODE
					&& mainChildNodes.item(i).getNodeName().endsWith(":" + SIGNATURE_TAG)) {
				rootSig.removeChild(mainChildNodes.item(i));
				removeEnvelopedSignatures(rootSig);
				return;
			}
		}
	}

	/**
	 * Comprueba si unos datos firmados tienen declarados una
	 * transformaci&oacute;n de tipo Base64.
	 * 
	 * @param rootSig
	 *            Nodo raiz de la firma.
	 * @param objectId
	 *            Identificador de los datos.
	 * @return {@code true} si la transformaci&oacute;n est&aacute; definida,
	 *         {@code false} en caso contrario.
	 */
	private static boolean isBase64TransformationDeclared(final Element rootSig, final String objectId) {
		if (objectId == null || objectId.trim().equals("")) {
			return false;
		}

		Element reference = null;
		final NodeList references = rootSig.getElementsByTagNameNS(XMLConstants.DSIGNNS, "Reference");
		for (int i = 0; i < references.getLength(); i++) {
			reference = (Element) references.item(i);
			if (reference.hasAttribute("URI") && ("#" + objectId).equals(reference.getAttribute("URI"))) { //$NON-NLS-3$
				break;
			}
			reference = null;
		}
		if (reference != null) {
			final NodeList transforms = reference.getElementsByTagNameNS(XMLConstants.DSIGNNS, "Transform");
			for (int i = 0; i < transforms.getLength(); i++) {
				if (((Element) transforms.item(i)).hasAttribute("Algorithm") && XMLConstants.BASE64_ENCODING
						.equals(((Element) transforms.item(i)).getAttribute("Algorithm"))) {
					return true;
				}
			}
		}
		return false;
	}

	public boolean isSign(final byte[] sign) {
		if (sign == null) {
			logger.warning("Se han introducido datos nulos para su comprobacion");
			return false;
		}

		try {
			// Carga el documento a validar
			final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);

			// JXades no captura un nodo de firma si se pasa este como raiz del
			// arbol de firmas, asi
			// que nos vemos obligados a crear un nodo padre, del que colgara
			// todo el arbol de firmas,
			// para que lo detecte correctamente
			Element rootNode = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(sign)).getDocumentElement();

			List<Node> signNodes = new ArrayList<>();
			if (rootNode.getNodeName().equals(SIGNATURE_NODE_NAME)) {
				signNodes.add(rootNode);
			}

			NodeList signatures = rootNode.getElementsByTagNameNS(XMLConstants.DSIGNNS, SIGNATURE_TAG);
			for (int i = 0; i < signatures.getLength(); i++) {
				signNodes.add(signatures.item(i));
			}

			// Si no se encuentran firmas, no es un documento de firma
			if (signNodes.size() == 0 || !XAdESUtil.checkSignNodes(signNodes)) {
				return false;
			}
		} catch (final Exception e) {
			return false;
		}
		return true;
	}

	public boolean isValidDataFile(final byte[] data) {
		if (data == null) {
			logger.warning("Se han introducido datos nulos para su comprobacion");
			return false;
		}
		return true;
	}

	public String getSignedName(final String originalName, final String inText) {
		return originalName + (inText != null ? inText : "") + ".xsig";
	}

	/**
	 * Devuelve un nuevo documento con ra&iacute;z "AFIRMA" del que cuelga el
	 * documento especificado.
	 * 
	 * @param docu
	 *            Documento que estar&aacute; contenido en el nuevo documento.
	 * @return Documento con ra&iacute;z "AFIRMA".
	 * @throws ParserConfigurationException
	 *             Cuando se produce un error al analizar el XML.
	 */
	static Document insertarNodoAfirma(final Document docu) throws ParserConfigurationException {

		// Nueva instancia de DocumentBuilderFactory que permita espacio de
		// nombres (necesario para XML)
		final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		// Crea un nuevo documento con la raiz "AFIRMA"
		final Document docAfirma = dbf.newDocumentBuilder().newDocument();
		final Element rootAfirma = docAfirma.createElement(AFIRMA);
		rootAfirma.setAttributeNS(null, ID_IDENTIFIER, "AfirmaRoot-" + UUID.randomUUID().toString());

		// Inserta el documento pasado por parametro en el nuevo documento
		rootAfirma.appendChild(docAfirma.adoptNode(docu.getDocumentElement()));
		docAfirma.appendChild(rootAfirma);

		return docAfirma;
	}

	@Override
	public List<SignInfo> getSigners(byte[] sign) throws InvalidFormatException, IOException {
		if (!isSign(sign)) {
			throw new InvalidFormatException("Los datos indicados no son una firma XAdES compatible");
		}

		// Obtenemos el arbol del documento
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		Document signDoc;

		try {
			signDoc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(sign));
		} catch (Exception e) {
			logger.warning("Se ha producido un error al obtener la estructura de firmas: " + e);
			return null;
		}

		// Obtenemos todas las firmas del documento y el SignatureValue de cada
		// una de ellas
		NodeList signatures = signDoc.getElementsByTagNameNS(XMLConstants.DSIGNNS, SIGNATURE_TAG);
		List<SignInfo> signInfos = new ArrayList<>();

		// Rellenamos la lista con los datos de las firmas del documento
		for (int i = 0; i < signatures.getLength(); i++) {
			Element signature = (Element) signatures.item(i);
			SignInfo signInfo = Utils.getSimpleSignInfoNode(Utils.guessXAdESNamespaceURL(signDoc.getDocumentElement()),
					signature);
			signInfos.add(signInfo);
		}

		return signInfos;
	}
}