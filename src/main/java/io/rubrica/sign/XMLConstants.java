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

package io.rubrica.sign;

import java.util.HashMap;
import java.util.Map;

/**
 * Clase con las constantes comunes compartidas por los distintos formatos de
 * firma XML.
 */
public final class XMLConstants {

	private XMLConstants() {
		// No permitimos la instanciacion
	}

	/** URI que define el NameSpace de firma XMLdSig (Compatible XAdES). */
	public static final String DSIGNNS = "http://www.w3.org/2000/09/xmldsig#";

	private static final String URL_SHA1_RSA = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
	private static final String URL_SHA256_RSA = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	private static final String URL_SHA384_RSA = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
	private static final String URL_SHA512_RSA = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
	private static final String URL_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
	private static final String URL_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
	private static final String URL_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
	private static final String URL_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";

	/** URIs de los algoritmos de firma */
	public static final Map<String, String> SIGN_ALGOS_URI;

	static {
		SIGN_ALGOS_URI = new HashMap<>();
		SIGN_ALGOS_URI.put(SignConstants.SIGN_ALGORITHM_SHA1WITHRSA, URL_SHA1_RSA);
		SIGN_ALGOS_URI.put(SignConstants.SIGN_ALGORITHM_SHA256WITHRSA, URL_SHA256_RSA);
		SIGN_ALGOS_URI.put(SignConstants.SIGN_ALGORITHM_SHA384WITHRSA, URL_SHA384_RSA);
		SIGN_ALGOS_URI.put(SignConstants.SIGN_ALGORITHM_SHA512WITHRSA, URL_SHA512_RSA);
	}

	/** Codificaci&oacute;n Base64 para firmas XMLDSig y XAdES. */
	public static final String BASE64_ENCODING = "http://www.w3.org/2000/09/xmldsig#base64";

	/**
	 * URIs de los algoritmos de hash. Las claves se encuentran en
	 * min&uacute;sculas.
	 */
	public static final Map<String, String> MESSAGEDIGEST_ALGOS_URI;
	static {
		MESSAGEDIGEST_ALGOS_URI = new HashMap<>();
		// Introducimos variantes para hacerlo mas robusto
		// SHA1
		MESSAGEDIGEST_ALGOS_URI.put("sha1", URL_SHA1);
		MESSAGEDIGEST_ALGOS_URI.put("sha-1", URL_SHA1);

		// SHA256
		MESSAGEDIGEST_ALGOS_URI.put("sha256", URL_SHA256);
		MESSAGEDIGEST_ALGOS_URI.put("sha-256", URL_SHA256);

		// SHA384
		MESSAGEDIGEST_ALGOS_URI.put("sha384", URL_SHA384);
		MESSAGEDIGEST_ALGOS_URI.put("sha-384", URL_SHA384);

		// SHA512
		MESSAGEDIGEST_ALGOS_URI.put("sha512", URL_SHA512);
		MESSAGEDIGEST_ALGOS_URI.put("sha-512", URL_SHA512);
	}

	/** MimeType por defecto para los datos firmados. */
	public static final String DEFAULT_MIMETYPE = "application/octet-stream";

	/** URI que define una referencia de tipo OBJECT. */
	public static final String OBJURI = "http://www.w3.org/2000/09/xmldsig#Object";
}