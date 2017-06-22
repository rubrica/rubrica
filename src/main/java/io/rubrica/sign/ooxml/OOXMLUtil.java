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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import io.rubrica.util.Utils;
import io.rubrica.xml.FileUtils;

/** Clase con m&eacute;todos de utilidad para las firmas OOXML. */
final class OOXMLUtil {

	/** Tipo de relaci&oacute;n correspondiente a una firma OOXML. */
	private static final String OOXML_SIGNATURE_RELATIONSHIP_TYPE = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature";

	/**
	 * Tipo de relaci&oacute;n correspondiente a la relaci&oacute;n de firmas
	 * OOXML.
	 */
	private static final String OOXML_SIGNATURE_ORIGIN_RELATIONSHIP_TYPE = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin";

	private static final Logger logger = Logger.getLogger(OOXMLUtil.class.getName());

	private OOXMLUtil() {
		// No permitimos la instanciacion
	}

	/**
	 * Cuenta el n&uacute;mero de firmas del documento OOXML.
	 * 
	 * @param ooxmlFile
	 *            Documento OOXML.
	 * @return N&uacute;mero de firma del documento OOXML.
	 * @throws ParserConfigurationException
	 *             Cuando hay problemas con el analizador SAX.
	 * @throws IOException
	 *             Cuando hay incosistencias de formato OOXML en los XML
	 *             internos del fichero.
	 * @throws SAXException
	 *             Cuando alguno de los XML internos del fichero no est&aacute;
	 *             bien formado.
	 */
	static int countOOXMLSignatures(final byte[] ooxmlFile)
			throws IOException, SAXException, ParserConfigurationException {
		final Relationship[] rels = getOOXMLSignaturesRelationships(ooxmlFile);
		return rels == null ? 0 : rels.length;
	}

	/**
	 * Cuenta el n&uacute;mero de firmas del documento OOXML. Si se produce
	 * alg&uacute;n error durante el an&aacute;lisis del fichero, se
	 * devolver&aacute; 0.
	 * 
	 * @param ooxmlFile
	 *            Documento OOXML.
	 * @return N&uacute;mero de firma del documento OOXML.
	 * @throws ParserConfigurationException
	 *             Cuando hay problemas con el analizador SAX.
	 * @throws IOException
	 *             Cuando hay incosistencias de formato OOXML en los XML
	 *             internos del fichero.
	 * @throws SAXException
	 *             Cuando alguno de los XML internos del fichero no est&aacute;
	 *             bien formado.
	 */
	private static Relationship[] getOOXMLSignaturesRelationships(byte[] ooxmlFile)
			throws IOException, SAXException, ParserConfigurationException {
		List<Relationship> relations = new ArrayList<>();

		try (ZipFile zipFile = FileUtils.createTempZipFile(ooxmlFile);) {
			// Comprobamos si existe la relacion de firmas del documento
			ZipEntry relsEntry = getSignaturesRelsEntry(zipFile);

			// Si no existe el fichero, el documento no contiene firmas
			if (relsEntry == null) {
				return new Relationship[0];
			}

			// Analizamos el fichero de relaciones
			RelationshipsParser parser = new RelationshipsParser(zipFile.getInputStream(relsEntry));

			// Contamos las relaciones de firma
			for (Relationship rel : parser.getRelationships()) {
				if (OOXML_SIGNATURE_RELATIONSHIP_TYPE.equals(rel.getType())) {
					relations.add(rel);
				}
			}
		}

		return relations.toArray(new Relationship[0]);
	}

	/**
	 * Recupera las firmas XMLdSig empotradas en el documento OOXML.
	 * 
	 * @param ooxmlFile
	 *            Documento OOXML.
	 * @return Firmas empotradas en el documento.
	 * @throws ParserConfigurationException
	 *             Cuando hay problemas con el analizador SAX.
	 * @throws IOException
	 *             Cuando hay incosistencias de formato OOXML en los XML
	 *             internos del fichero.
	 * @throws SAXException
	 *             Cuando alguno de los XML internos del fichero no est&aacute;
	 *             bien formado.
	 */
	static byte[][] getOOXMLSignatures(byte[] ooxmlFile)
			throws IOException, SAXException, ParserConfigurationException {

		List<byte[]> relations = new ArrayList<>();

		try (ZipFile zipFile = FileUtils.createTempZipFile(ooxmlFile);) {
			// Comprobamos si existe la relacion de firmas del documento
			ZipEntry relsEntry = getSignaturesRelsEntry(zipFile);

			// Si no existe el fichero, el documento no contiene firmas
			if (relsEntry == null) {
				return new byte[0][];
			}

			// Analizamos el fichero de relaciones
			RelationshipsParser parser = new RelationshipsParser(zipFile.getInputStream(relsEntry));

			// Contamos las relaciones de firma
			for (Relationship rel : parser.getRelationships()) {
				if (OOXML_SIGNATURE_RELATIONSHIP_TYPE.equals(rel.getType())) {
					// Comprobamos que exista el firma referenciada
					String target = rel.getTarget();
					ZipEntry signEntry = zipFile.getEntry("_xmlsignatures/" + target);
					if (signEntry == null) {
						signEntry = zipFile.getEntry("_xmlsignatures\\" + target);
					}
					if (signEntry == null) {
						logger.severe("El documento OOXML no contiene las firmas declaradas");
						zipFile.close();
						return new byte[0][];
					}

					// Guardamos la firma
					try {
						relations.add(Utils.getDataFromInputStream(zipFile.getInputStream(signEntry)));
					} catch (final Exception e) {
						logger.severe("No se pudo leer una de las firmas del documento OOXML: " + e);
						zipFile.close();
						return new byte[0][];
					}
				}
			}
		}

		return relations.toArray(new byte[0][]);
	}

	/**
	 * Recupera la entrada con la relaci&oacute;n de firmas del documento.
	 * 
	 * @param ooxmlZipFile
	 *            Fichero OOXML.
	 * @return Entrada con la relaci&oacute;n de firmas.
	 */
	private static ZipEntry getSignaturesRelsEntry(ZipFile ooxmlZipFile) {
		ZipEntry relsEntry = ooxmlZipFile.getEntry("_rels/.rels");

		if (relsEntry == null) {
			relsEntry = ooxmlZipFile.getEntry("_rels\\.rels");
		}

		// Analizamos el fichero de relaciones
		RelationshipsParser parser;
		try {
			parser = new RelationshipsParser(ooxmlZipFile.getInputStream(relsEntry));
		} catch (Exception e) {
			logger.severe("Error en la lectura del OOXML: " + e);
			return null;
		}

		ZipEntry signsEntry = null;
		for (Relationship rel : parser.getRelationships()) {
			if (OOXML_SIGNATURE_ORIGIN_RELATIONSHIP_TYPE.equals(rel.getType())) {
				String middleTarget = rel.getTarget().substring(0, "_xmlsignatures".length() + 1);
				String target = rel.getTarget().substring("_xmlsignatures".length() + 1);
				signsEntry = ooxmlZipFile.getEntry(middleTarget + "_rels/" + target + ".rels");
				if (signsEntry == null) {
					signsEntry = ooxmlZipFile.getEntry(middleTarget + "_rels\\" + target + ".rels");
				}
				break;
			}
		}

		return signsEntry;
	}
}