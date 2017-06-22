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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import io.rubrica.core.RubricaException;
import io.rubrica.sign.Signer;
import io.rubrica.sign.SimpleSignInfo;
import io.rubrica.sign.ooxml.relprovider.OOXMLProvider;
import io.rubrica.sign.xades.XAdESSigner;
import io.rubrica.xml.Utils;

public class OOXMLSigner implements Signer {

	private static final Logger logger = Logger.getLogger(OOXMLSigner.class.getName());

	/**
	 * Consutruye un firmador OOXML, comprobando que se cuente con un JRE
	 * adecuado.
	 */
	public OOXMLSigner() {
		// Proveedor XMLDSig
		Utils.installXmlDSigProvider();

		// Proveedor de transformadas de relacion OOXML.
		try {
			Provider provider = Security.getProvider(OOXMLProvider.RELATIONSHIP_TRANSFORM_PROVIDER_NAME);
			if (provider == null) {
				Security.addProvider(new OOXMLProvider());
			}
		} catch (Throwable e) {
			logger.log(Level.WARNING, "Error en la instalacion del proveedor OOXML: " + e, e);
		}
	}

	public byte[] sign( byte[] data,  String algorithm,  PrivateKey key,
			 Certificate[] certChain,  Properties extraParams)
			throws RubricaException, IOException {

		// Comprobamos si es un documento OOXML valido.
		// if (!OfficeAnalizer.isOOXMLDocument(data)) {
		// throw new FormatFileException("Los datos introducidos no se
		// corresponden con un documento OOXML");
		// }

		if (certChain == null || certChain.length < 1) {
			throw new IllegalArgumentException("Debe proporcionarse a menos el certificado del firmante");
		}

		 Properties xParams = extraParams != null ? extraParams : new Properties();

		// Office 2016 no acepta cadenas, solo debe estar el cert del firmante
		return signOOXML(data, algorithm, key, new X509Certificate[] { (X509Certificate) certChain[0] }, xParams);
	}

	private static byte[] signOOXML(final byte[] ooxmlDocument, final String algorithm, final PrivateKey key,
			final X509Certificate[] certChain, final Properties xParams) throws RubricaException {

		if (key == null) {
			throw new IllegalArgumentException("No se ha proporcionado una clave valida");
		}

		try {
			return OOXMLZipHelper.outputSignedOfficeOpenXMLDocument(ooxmlDocument,
					OOXMLXAdESSigner.getSignedXML(ooxmlDocument, algorithm, key, certChain, xParams));
		} catch (final Exception e) {
			throw new RubricaException("Error durante la firma OOXML: " + e, e);
		}
	}

	public List<SimpleSignInfo> getSignInfos(byte[] sign) {
		if (sign == null) {
			throw new IllegalArgumentException("Los datos de firma introducidos son nulos");
		}

		// if (!isSign(sign)) {
		// logger.severe("La firma indicada no es de tipo OOXML");
		// return null;
		// }

		// Las firmas contenidas en el documento OOXML son de tipo XMLdSig asi
		// que utilizaremos el signer de este tipo para gestionar el arbol de
		// firmas
		XAdESSigner xmldsigSigner = new XAdESSigner();

		// Recuperamos las firmas individuales del documento y creamos el arbol
		List<SimpleSignInfo> singInfos = new ArrayList<>();

		try {
			for (byte[] elementSign : OOXMLUtil.getOOXMLSignatures(sign)) {
				// Recuperamos el arbol de firmas de la firma individual. Ya que
				// esta sera una firma simple solo debe contener un nodo de
				// firma.
				// Ignoramos la raiz del arbol, que contiene el ejemplo
				// representativo de los datos firmados y no de la propia firma.
				List<SimpleSignInfo> signInfo = xmldsigSigner.getSignersStructure(elementSign);
				singInfos.add(signInfo.get(0));
			}

			return singInfos;
		} catch (Exception e) {
			logger.severe("La estructura de una de las firmas elementales no es valida: " + e);
			return null;
		}
	}
}