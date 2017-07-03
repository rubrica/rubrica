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

package io.rubrica.sign.odf;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import io.rubrica.core.RubricaException;
import io.rubrica.core.Util;
import io.rubrica.sign.InvalidFormatException;
import io.rubrica.sign.SignInfo;
import io.rubrica.sign.Signer;
import io.rubrica.sign.XMLConstants;
import io.rubrica.util.Utils;
import nu.xom.canonical.Canonicalizer;
import nu.xom.converters.DOMConverter;

public class ODFSigner implements Signer {

	private static final Logger logger = Logger.getLogger(ODFSigner.class.getName());

	private static final String OPENOFFICE = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";
	private static final String SIGN_ALGORITHM_SHA1WITHRSA = "SHA1withRSA";
	private static final String MANIFEST_PATH = "META-INF/manifest.xml";
	private static final String SIGNATURES_PATH = "META-INF/documentsignatures.xml";
	private static final String CANONICAL_XML_ALGORITHM = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
	private static final String XMLDSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";

	/** Algoritmo de huella digital por defecto para las referencias XML. */
	private static final String DEFAULT_DIGEST_METHOD = DigestMethod.SHA1;

	private static final String DIGEST_METHOD_ALGORITHM_NAME = "SHA1";

	/** Mimetypes de los formatos ODF soportados. */
	private static final Set<String> SUPPORTED_FORMATS;

	static {
		SUPPORTED_FORMATS = new HashSet<>();
		SUPPORTED_FORMATS.add("application/vnd.oasis.opendocument.text");
		SUPPORTED_FORMATS.add("application/vnd.oasis.opendocument.spreadsheet");
		SUPPORTED_FORMATS.add("application/vnd.oasis.opendocument.presentation");
	}

	/**
	 * Indica si los datos son un documento ODF susceptible de ser firmado.
	 * 
	 * @param data
	 *            Datos a comprobar
	 * @return <code>true</code> si los datos son un documento ODF susceptible
	 *         de ser firmado, <code>false</code> en caso contrario
	 */
	public boolean isValidDataFile(byte[] data) {
		File odfFile;

		try {
			odfFile = createTempFile(data);
			odfFile.deleteOnExit();
		} catch (Exception e) {
			logger.warning("No se pudo crear una copia del fichero para su analisis, se devolvera false: " + e);
			return false;
		}

		// Si el mimetype del fichero no se ajusta a alguno de los MimeTypes
		// soportados
		// para firma ODF se lanzara una excepcion, en ese caso deducimos que no
		// es un
		// fichero valido
		String mimetype = null;
		try {
			mimetype = getODFMimeType(odfFile);
		} catch (final Exception e) {
			return false;
		}

		// Sera valido si el mimetype coincide con alguno de los formatos ODF
		// soportados
		return mimetype != null && SUPPORTED_FORMATS.contains(mimetype);
	}

	public boolean isSign(byte[] signData) throws IOException {
		if (!isValidDataFile(signData)) {
			return false;
		}

		File odfFile;

		try {
			odfFile = createTempFile(signData);
			odfFile.deleteOnExit();
		} catch (Exception e) {
			logger.warning("No se pudo crear una copia del fichero para su analisis, se devolvera false: " + e);
			return false;
		}

		// carga el fichero zip
		try (ZipFile zf = new ZipFile(odfFile);) {
			// obtiene el archivo mimetype
			return zf.getEntry(SIGNATURES_PATH) != null;
		}
	}

	@Override
	public byte[] sign(byte[] data, String algorithm, PrivateKey key, Certificate[] certChain, Properties extraParams)
			throws RubricaException, IOException {

		if (!SIGN_ALGORITHM_SHA1WITHRSA.equals(algorithm)) {
			logger.warning("Se ha indicado '" + algorithm
					+ "' como algoritmo de firma, pero se usara 'SHA1withRSA' por necesidades del formato ODF");
		}

		String fullPath = MANIFEST_PATH;
		boolean isCofirm = false;

		try {
			// Genera el archivo zip temporal a partir del InputStream de
			// entrada
			File zipFile = File.createTempFile("sign", ".zip");

			try (FileOutputStream fos = new FileOutputStream(zipFile)) {
				fos.write(data);
				fos.flush();
			}

			zipFile.deleteOnExit();

			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			// carga el fichero zip
			try (ZipFile zf = new ZipFile(zipFile)) {
				byte[] manifestData;

				// obtiene el archivo manifest.xml, que indica los ficheros que
				// contiene el ODF
				try (InputStream manifest = zf.getInputStream(zf.getEntry(fullPath))) {
					manifestData = Utils.getDataFromInputStream(manifest);
				}

				// obtiene el documento manifest.xml y su raiz
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				dbf.setNamespaceAware(true);
				Document docManifest = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(manifestData));
				Element rootManifest = docManifest.getDocumentElement();

				// recupera todos los nodos de manifest.xml
				NodeList listFileEntry = rootManifest.getElementsByTagName("manifest:file-entry");

				// Datos necesarios para la firma

				// MessageDigest
				MessageDigest md;

				try {
					md = MessageDigest.getInstance(DIGEST_METHOD_ALGORITHM_NAME);
				} catch (Exception e) {
					throw new RubricaException(
							"No se ha podido obtener un generador de huellas digitales con el algoritmo "
									+ DIGEST_METHOD_ALGORITHM_NAME + ": " + e,
							e);
				}

				// XMLSignatureFactory
				XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

				// DigestMethod
				DigestMethod dm;

				try {
					dm = fac.newDigestMethod(DEFAULT_DIGEST_METHOD, null);
				} catch (Exception e) {
					throw new RubricaException(
							"No se ha podido obtener un generador de huellas digitales con el algoritmo: "
									+ DEFAULT_DIGEST_METHOD,
							e);
				}

				// Configuramos las transformaciones y referencias

				// Transforms
				List<Transform> transformList = new ArrayList<>(1);
				transformList.add(fac.newTransform(Canonicalizer.CANONICAL_XML, (TransformParameterSpec) null));

				// References
				List<Reference> referenceList = new ArrayList<>();

				// Anadimos tambien referencias manualmente al propio
				// manifest.xml y
				// al mimetype

				// mimetype es una referencia simple, porque no es XML
				referenceList.add(fac.newReference("mimetype", dm, null, null, null,
						md.digest(Utils.getDataFromInputStream(
								// Recupera el fichero
								zf.getInputStream(zf.getEntry("mimetype"))))));

				referenceList
						.add(fac.newReference(MANIFEST_PATH, dm, transformList, null, null,
								md.digest(canonicalizeXml(dbf.newDocumentBuilder()
										.parse(new ByteArrayInputStream(manifestData)).getDocumentElement(),
										CANONICAL_XML_ALGORITHM))));

				// para cada nodo de manifest.xml
				Reference reference;
				for (int i = 0; i < listFileEntry.getLength(); i++) {
					fullPath = ((Element) listFileEntry.item(i)).getAttribute("manifest:full-path");

					// si es un archivo
					if (!fullPath.endsWith("/")) {

						// y es uno de los siguientes archivos xml
						if (fullPath.equals("content.xml") || fullPath.equals("meta.xml")
								|| fullPath.equals("styles.xml") || fullPath.equals("settings.xml")) {

							// crea la referencia
							reference = fac.newReference(fullPath.replaceAll(" ", "%20"), dm, transformList, null, null,
									// Obtiene su forma canonica y su
									// DigestValue
									md.digest(canonicalizeXml(dbf.newDocumentBuilder()
											.parse(zf.getInputStream(zf.getEntry(fullPath))).getDocumentElement(),
											CANONICAL_XML_ALGORITHM)));
						}

						// si no es uno de los archivos xml
						else {
							// crea la referencia
							reference = fac.newReference(fullPath.replaceAll(" ", "%20"), dm, null, null, null,
									md.digest(Utils.getDataFromInputStream(
											// Recupera el fichero
											zf.getInputStream(zf.getEntry(fullPath)))));
						}

						if (!fullPath.equals(SIGNATURES_PATH)) {
							referenceList.add(reference);
						} else {
							// Para mantener la compatibilidad con OpenOffice
							// 3.1?
							isCofirm = true;
						}
					}
				}

				// Si se encuentra el fichero de firmas en el documento, la
				// nueva firma se debe agregar a el
				if (!isCofirm && zf.getEntry(SIGNATURES_PATH) != null) {
					isCofirm = true;
				}

				Document docSignatures;
				Element rootSignatures;
				// si es cofirma
				if (isCofirm) {
					// recupera el documento de firmas y su raiz
					docSignatures = dbf.newDocumentBuilder().parse(zf.getInputStream(zf.getEntry(SIGNATURES_PATH)));
					rootSignatures = docSignatures.getDocumentElement();
				} else {
					// crea un nuevo documento de firmas
					docSignatures = dbf.newDocumentBuilder().newDocument();
					rootSignatures = docSignatures.createElement("document-signatures");
					rootSignatures.setAttribute("xmlns", OPENOFFICE);
					docSignatures.appendChild(rootSignatures);
				}

				// Ids de Signature y SignatureProperty
				String signatureId = UUID.randomUUID().toString();
				String signaturePropertyId = UUID.randomUUID().toString();

				// referencia a SignatureProperty
				referenceList.add(fac.newReference("#" + signaturePropertyId, dm));

				// contenido de SignatureProperty
				Element content = docSignatures.createElement("dc:date");
				content.setAttribute("xmlns:dc", "http://purl.org/dc/elements/1.1/");
				content.setTextContent(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss,SS").format(new Date()));
				List<XMLStructure> contentList = new ArrayList<>();
				contentList.add(new DOMStructure(content));

				// SignatureProperty
				List<SignatureProperty> spList = new ArrayList<>();
				spList.add(fac.newSignatureProperty(contentList, "#" + signatureId, signaturePropertyId));

				// SignatureProperties
				List<SignatureProperties> spsList = new ArrayList<>();
				spsList.add(fac.newSignatureProperties(spList, null));

				// Object
				List<XMLObject> objectList = new ArrayList<>();
				objectList.add(fac.newXMLObject(spsList, null, null, null));

				// Preparamos el KeyInfo
				KeyInfoFactory kif = fac.getKeyInfoFactory();
				List<Object> x509Content = new ArrayList<>();
				X509Certificate cert = (X509Certificate) certChain[0];
				x509Content.add(cert.getSubjectX500Principal().getName());
				x509Content.add(cert);

				// genera la firma
				fac.newXMLSignature(
						// SignedInfo
						fac.newSignedInfo(
								// CanonicalizationMethod
								fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
										(C14NMethodParameterSpec) null),
								fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), referenceList),
						// KeyInfo
						kif.newKeyInfo(Collections.singletonList(kif.newX509Data(x509Content)), null), objectList,
						signatureId, null).sign(new DOMSignContext(key, rootSignatures));

				// crea un nuevo fichero zip
				try (ZipOutputStream zos = new ZipOutputStream(baos);) {
					// copia el contenido del zip original en el nuevo excepto
					// el documento de firmas y manifest.xml
					Enumeration<? extends ZipEntry> e = zf.entries();
					ZipEntry ze;
					ZipEntry zeOut;
					while (e.hasMoreElements()) {
						ze = e.nextElement();
						zeOut = new ZipEntry(ze.getName());
						if (!ze.getName().equals(SIGNATURES_PATH) && !ze.getName().equals(MANIFEST_PATH)) {
							zos.putNextEntry(zeOut);
							zos.write(Utils.getDataFromInputStream(zf.getInputStream(ze)));
						}
					}

					// anade el documento de firmas
					zos.putNextEntry(new ZipEntry(SIGNATURES_PATH));
					ByteArrayOutputStream baosXML = new ByteArrayOutputStream();
					writeXML(baosXML, rootSignatures, false);
					zos.write(baosXML.toByteArray());
					zos.closeEntry();

					// anade manifest.xml
					zos.putNextEntry(new ZipEntry(MANIFEST_PATH));
					ByteArrayOutputStream baosManifest = new ByteArrayOutputStream();
					writeXML(baosManifest, rootManifest, false);
					zos.write(baosManifest.toByteArray());
					zos.closeEntry();
				}
			}

			return baos.toByteArray();

		} catch (SAXException saxex) {
			throw new FormatFileException("Estructura de archivo no valida '" + fullPath + "': " + saxex);
		} catch (Exception e) {
			throw new RubricaException("No ha sido posible generar la firma ODF: " + e, e);
		}
	}

	private static void toString(Document newDoc) throws Exception {
		DOMSource domSource = new DOMSource(newDoc);
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		StringWriter sw = new StringWriter();
		StreamResult sr = new StreamResult(sw);
		transformer.transform(domSource, sr);
		System.out.println(sw.toString());
	}

	public List<SignInfo> getSigners(byte[] sign) throws InvalidFormatException, IOException {
		if (!isSign(sign)) {
			throw new InvalidFormatException("Los datos indicados no se corresponden con un ODF firmado");
		}

		try {
			// Genera un archivo zip temporal a partir del byte[] de entrada
			File zipFile = File.createTempFile("sign", ".zip");
			try (final FileOutputStream fos = new FileOutputStream(zipFile);) {
				fos.write(sign);
				fos.flush();
			}

			List<SignInfo> signInfos = new ArrayList<>();

			try (ZipFile zf = new ZipFile(zipFile);
					InputStream signIs = zf.getInputStream(zf.getEntry(SIGNATURES_PATH))) {

				// Recupera la raiz del documento de firmas
				DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				dbf.setNamespaceAware(true);

				// TODO
				// toString(dbf.newDocumentBuilder().parse(signIs));

				Element root = dbf.newDocumentBuilder().parse(signIs).getDocumentElement();

				// Obtiene todas las firmas
				NodeList signatures = root.getElementsByTagNameNS(XMLDSIG_NAMESPACE, "Signature");

				int numSignatures = signatures.getLength();

				for (int i = 0; i < numSignatures; i++) {
					Element signature = (Element) signatures.item(i);
					SignInfo signInfo = getSignInfo(signature);
					signInfos.add(signInfo);
				}
			}

			zipFile.deleteOnExit();

			return signInfos;
		} catch (Exception e) {
			logger.warning("Se ha producido un error al obtener la estructura de firmas: " + e);
			throw new InvalidFormatException("Se ha producido un error al obtener la estructura de firmas");
		}
	}

	private static byte[] canonicalizeXml(org.w3c.dom.Element element, String algorithm) throws IOException {
		nu.xom.Element xomElement = DOMConverter.convert(element);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Canonicalizer canonicalizer = new Canonicalizer(baos, algorithm);
		canonicalizer.write(xomElement);
		return baos.toByteArray();
	}

	private static void writeXML(OutputStream outStream, Node node, boolean indent) {
		writeXML(new BufferedWriter(new OutputStreamWriter(outStream, Charset.forName("UTF-8"))), node, indent);
	}

	private static void writeXML(Writer writer, Node node, boolean indent) {
		try {
			Transformer serializer = TransformerFactory.newInstance().newTransformer();
			serializer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

			if (indent) {
				serializer.setOutputProperty(OutputKeys.INDENT, "yes");
			}

			serializer.transform(new DOMSource(node), new StreamResult(writer));
		} catch (Exception ex) {
			logger.severe("Error al escribir el cuerpo del XML: " + ex);
		}
	}

	private static String getODFMimeType(File odfFile) throws IOException {
		// carga el fichero zip
		try (ZipFile zf = new ZipFile(odfFile);) {
			// obtiene el archivo mimetype
			final ZipEntry entry = zf.getEntry("mimetype");
			if (entry != null) {
				return new String(Util.getDataFromInputStream(zf.getInputStream(entry)));
			}
		}
		return null;
	}

	/**
	 * Crea un fichero temporal con los datos.
	 * 
	 * @param data
	 *            Datos del fichero.
	 * @return Fichero generado.
	 * @throws IOException
	 *             Cuando se produce un error durante la generaci&oacute;n.
	 */
	private File createTempFile(byte[] data) throws IOException {
		// Genera el archivo zip temporal a partir del InputStream de entrada
		final File zipFile = File.createTempFile("sign", ".zip");
		try (final FileOutputStream fos = new FileOutputStream(zipFile);) {
			fos.write(data);
			fos.flush();
		}
		return zipFile;
	}

	private SignInfo getSignInfo(Element signature) {
		// Recupera la fecha de firma
		Date signingTime = null;

		try {
			signingTime = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").parse(
					((Element) signature.getElementsByTagNameNS("http://purl.org/dc/elements/1.1/", "date").item(0))
							.getTextContent());
		} catch (Exception e) {
			logger.warning("No se ha podido recuperar la fecha de firma: " + e);
		}

		List<X509Certificate> certChain = new ArrayList<>();
		NodeList signatureNodes = signature.getElementsByTagNameNS(XMLConstants.DSIGNNS, "X509Certificate");

		for (int i = 0; i < signatureNodes.getLength(); i++) {
			certChain.add(Utils.getCertificate(signatureNodes.item(i)));
		}

		SignInfo signInfo = new SignInfo(certChain.toArray(new X509Certificate[certChain.size()]), signingTime);
		signInfo.setSignAlgorithm(
				((Element) signature.getElementsByTagNameNS(XMLConstants.DSIGNNS, "SignatureMethod").item(0))
						.getAttribute("Algorithm"));

		byte[] pkcs1;
		try {
			pkcs1 = Base64.getDecoder()
					.decode(((Element) signature.getElementsByTagNameNS(XMLConstants.DSIGNNS, "SignatureValue").item(0))
							.getTextContent().trim().replace("\r", "").replace("\n", "").replace(" ", "").replace("\t",
									""));
		} catch (Exception e) {
			logger.warning("No se pudo extraer el PKCS#1 de una firma: " + e);
			pkcs1 = null;
		}

		signInfo.setPkcs1(pkcs1);

		return signInfo;
	}

}