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

package io.rubrica.sign;

import java.util.Locale;

/** Constantes relativas a las firmas digitales. */
public final class SignConstants {

	// ************************************************************
	// ************* FORMATOS DE FIRMA*****************************
	// ************************************************************

	/**
	 * Identificador del formato de firma seleccionado autom&aacute;ticamente.
	 */
	public static final String SIGN_FORMAT_AUTO = "auto";

	/** Identificador de la firma CMS. */
	public static final String SIGN_FORMAT_CMS = "CMS/PKCS#7";

	/** Identificador de la firma CAdES ASiC-S. */
	public static final String SIGN_FORMAT_CADES_ASIC_S = "CAdES-ASiC-S";

	/** Identificador de la firma CAdES ASiC-S trif&aacute;sica. */
	public static final String SIGN_FORMAT_CADES_ASIC_S_TRI = "CAdES-ASiC-S-tri";

	/** Identificador de la firma CAdES. */
	public static final String SIGN_FORMAT_CADES = "CAdES";

	/** Identificador de la firma CAdES trif&aacute;sica. */
	public static final String SIGN_FORMAT_CADES_TRI = "CAdEStri";

	/** Identificador de la firma PKCS1 (RAW). */
	public static final String SIGN_FORMAT_PKCS1 = "NONE";

	/** Identificador de la firma XAdES-ASiC-S. */
	public static final String SIGN_FORMAT_XADES_ASIC_S = "XAdES-ASiC-S";

	/** Identificador de la firma XAdES-ASiC-S trif&aacute;sica. */
	public static final String SIGN_FORMAT_XADES_ASIC_S_TRI = "XAdES-ASiC-S-tri";

	/** Identificador de la firma XAdES Internally Detached. */
	public static final String SIGN_FORMAT_XADES_DETACHED = "XAdES Detached";

	/** Identificador de la firma XAdES Externally Detached. */
	public static final String SIGN_FORMAT_XADES_EXTERNALLY_DETACHED = "XAdES Externally Detached";

	/** Identificador de la firma XAdES Enveloped. */
	public static final String SIGN_FORMAT_XADES_ENVELOPED = "XAdES Enveloped";

	/** Identificador de la firma XAdES Enveloping. */
	public static final String SIGN_FORMAT_XADES_ENVELOPING = "XAdES Enveloping";

	/** Identificador de la firma XAdES por defecto. */
	public static final String SIGN_FORMAT_XADES = "XAdES";

	/** Identificador de la firma XAdES trif&aacute;sica. */
	public static final String SIGN_FORMAT_XADES_TRI = "XAdEStri";

	/** Identificador de la firma XMLDsig Detached. */
	public static final String SIGN_FORMAT_XMLDSIG_DETACHED = "XMLDSig Detached";

	/** Identificador de la firma XMLdSig Externally Detached. */
	public static final String SIGN_FORMAT_XMLDSIG_EXTERNALLY_DETACHED = "XMLDSig Externally Detached";

	/** Identificador de la firma XMLDsig Enveloped. */
	public static final String SIGN_FORMAT_XMLDSIG_ENVELOPED = "XMLDSig Enveloped";

	/** Identificador de la firma XMLDsig Enveloping. */
	public static final String SIGN_FORMAT_XMLDSIG_ENVELOPING = "XMLDSig Enveloping";

	/** Identificador de la firma XMLDSig (<i>XML Digital Signature</i>). */
	public static final String SIGN_FORMAT_XMLDSIG = "XMLDSig";

	/** Identificador de la firma OOXML (<i>Office Open XML</i>). */
	public static final String SIGN_FORMAT_OOXML = "OOXML (Office Open XML)";

	/** Identificador alternativo n&uacute;mero 1 para el formato OOXML. */
	public static final String SIGN_FORMAT_OOXML_ALT1 = "OOXML";

	/** Identificador de la firma ODF (<i>Open Document Format</i>). */
	public static final String SIGN_FORMAT_ODF = "ODF (Open Document Format)";

	/** Identificador alternativo n&uacute;mero 1 para el formato ODF. */
	public static final String SIGN_FORMAT_ODF_ALT1 = "ODF";

	/** Identificador de la firma Adobe PDF. */
	public static final String SIGN_FORMAT_PDF = "Adobe PDF";

	/** Identificador de la firma Adobe PDF trif&aacute;sica. */
	public static final String SIGN_FORMAT_PDF_TRI = "Adobe PDF TriPhase";

	/** Identificador de la firma PAdES. */
	public static final String SIGN_FORMAT_PADES = "PAdES";

	/** Identificador de la firma PAdES trif&aacute;sica. */
	public static final String SIGN_FORMAT_PADES_TRI = "PAdEStri";

	/** Identificador de la firma SOAP. */
	public static final String SIGN_FORMAT_SOAP = "SOAP";

	/** Identificador de la firma Factura-e (derivado de XAdES-EPES). */
	public static final String SIGN_FORMAT_FACTURAE = "FacturaE";

	/**
	 * Identificador de la firma Factura-e (derivado de XAdES-EPES)
	 * trif&aacute;sica.
	 */
	public static final String SIGN_FORMAT_FACTURAE_TRI = "FacturaEtri";

	/**
	 * Identificador alternativo de la firma Factura-e (derivado de XAdES-EPES).
	 */
	public static final String SIGN_FORMAT_FACTURAE_ALT1 = "Factura-e";

	/** Formato de firma por defecto. */
	public static final String DEFAULT_SIGN_FORMAT = SIGN_FORMAT_CADES;

	// ************************************************************
	// ************* OPERACIONES **********************************
	// ************************************************************

	/** Identificador de la operaci&oacute;n de firma masiva. */
	public static final String MASSIVE_OPERATION_SIGN = "FIRMAR";

	/** Identificador de la operaci&oacute;n de cofirma masiva. */
	public static final String MASSIVE_OPERATION_COSIGN = "COFIRMAR";

	/**
	 * Identificador de la operaci&oacute;n de contrafirma masiva de todo el
	 * &aacute;rbol de firma.
	 */
	public static final String MASSIVE_OPERATION_COUNTERSIGN_TREE = "CONTRAFIRMAR_ARBOL";

	/**
	 * Identificador de la operaci&oacute;n de contrafirma masiva de nodos hoja
	 * de firma.
	 */
	public static final String MASSIVE_OPERATION_COUNTERSIGN_LEAFS = "CONTRAFIRMAR_HOJAS";

	/** Operaci&oacute;n masiva por defecto. */
	public static final String DEFAULT_MASSIVE_OPERATION = MASSIVE_OPERATION_SIGN;

	/**
	 * Envoltorio binario de tipo Data (datos envueltos en un envoltorio
	 * PKCS#7).
	 */
	public static final String CMS_CONTENTTYPE_DATA = "Data";

	/** Firma binaria de tipo Signed Data */
	public static final String CMS_CONTENTTYPE_SIGNEDDATA = "SignedData";

	/** Envoltorio binario de tipo Digest. */
	public static final String CMS_CONTENTTYPE_DIGESTEDDATA = "DigestedData";

	/** Envoltorio binario de tipo AuthenticatedEnvelopedData. */
	public static final String CMS_CONTENTTYPE_COMPRESSEDDATA = "CompressedData";

	/** Firma binaria de tipo Encrypted Data */
	public static final String CMS_CONTENTTYPE_ENCRYPTEDDATA = "EncryptedData";

	/** Envoltorio binario de tipo Enveloped (sobre digital). */
	public static final String CMS_CONTENTTYPE_ENVELOPEDDATA = "EnvelopedData";

	/** Envoltorio binario de tipo Signed and Enveloped. */
	public static final String CMS_CONTENTTYPE_SIGNEDANDENVELOPEDDATA = "SignedAndEnvelopedData";

	/** Envoltorio binario de tipo AuthenticatedData. */
	public static final String CMS_CONTENTTYPE_AUTHENTICATEDDATA = "AuthenticatedData";

	/** Envoltorio binario de tipo AuthenticatedEnvelopedData. */
	public static final String CMS_CONTENTTYPE_AUTHENVELOPEDDATA = "AuthEnvelopedData";

	/** Envoltorio binario por defecto. */
	public static final String DEFAULT_CMS_CONTENTTYPE = CMS_CONTENTTYPE_ENVELOPEDDATA;

	/** OID por defecto para los datos firmados. */
	public static final String DEFAULT_OID_TO_SIGN = "1.3.6.1.4.1.1466.115.121.1.40"; // Octect

	// ************************************************************
	// ******************** SUBFILTROS PDF ************************
	// ************************************************************

	/** Filtro para firma PAdES-B&aacute;sico. */
	public static final String PADES_SUBFILTER_BASIC = "adbe.pkcs7.detached";

	/** Filtro para firma PAdES-BES. */
	public static final String PADES_SUBFILTER_BES = "ETSI.CAdES.detached";

	// ************************************************************
	// ************* ALGORITMOS DE FIRMA **************************
	// ************************************************************

	/** Algoritmo de firma SHA1withRSA. */
	public static final String SIGN_ALGORITHM_SHA1WITHRSA = "SHA1withRSA";

	/** Algoritmo de firma SHA256withRSA. */
	public static final String SIGN_ALGORITHM_SHA256WITHRSA = "SHA256withRSA";

	/** Algoritmo de firma SHA384withRSA. */
	public static final String SIGN_ALGORITHM_SHA384WITHRSA = "SHA384withRSA";

	/** Algoritmo de firma SHA512withRSA. */
	public static final String SIGN_ALGORITHM_SHA512WITHRSA = "SHA512withRSA";

	/**
	 * Algoritmo de firma RSA que no incluye la generaci&oacute;n de la huella
	 * digital (NONEwithRSA).
	 */
	public static final String SIGN_ALGORITHM_NONEWITHRSA = "NONEwithRSA";

	/** Algoritmo de firma SHA1withDSA. */
	public static final String SIGN_ALGORITHM_SHA1WITHDSA = "SHA1withDSA";

	/** Algoritmo de firma SHA1withECDSA. */
	public static final String SIGN_ALGORITHM_SHA1WITHECDSA = "SHA1withECDSA";

	/**
	 * Algoritmo de firma ECDSA que no incluye la generaci&oacute;n de la huella
	 * digital (NONEwithEDSSA).
	 */
	public static final String SIGN_ALGORITHM_NONEWITHECDSA = "NONEwithECDSA";

	/** Algoritmos de firma soportados. */
	public static final String[] SUPPORTED_SIGN_ALGOS = new String[] { SIGN_ALGORITHM_SHA1WITHRSA,
			SIGN_ALGORITHM_NONEWITHRSA, SIGN_ALGORITHM_SHA256WITHRSA, SIGN_ALGORITHM_SHA384WITHRSA,
			SIGN_ALGORITHM_SHA512WITHRSA, SIGN_ALGORITHM_SHA1WITHECDSA, SIGN_ALGORITHM_NONEWITHECDSA };

	/** Algoritmo de firma por defecto. */
	public static final String DEFAULT_SIGN_ALGO = SIGN_ALGORITHM_SHA512WITHRSA;

	// ************************************************************
	// ****************** MODOS DE FIRMA **************************
	// ************************************************************

	/**
	 * Identificador del modo de firma Explicita (Los datos NO se incluyen en la
	 * firma).
	 */
	public static final String SIGN_MODE_EXPLICIT = "explicit";

	/**
	 * Identificador del modo de firma Implicita (Los datos SI se incluyen en la
	 * firma).
	 */
	public static final String SIGN_MODE_IMPLICIT = "implicit";

	/** Modo de firma por defecto. */
	public static final String DEFAULT_SIGN_MODE = SIGN_MODE_EXPLICIT;

	private SignConstants() {
		// No permitimos la instanciacion
	}

	/**
	 * Obtiene el nombre de un algoritmo de huella digital a partir de una de
	 * las variantes de este.
	 * 
	 * @param pseudoName
	 *            Nombre o variante del nombre del algoritmo de huella digital
	 * @return Nombre del algoritmo de huella digital
	 */
	public static String getDigestAlgorithmName(final String pseudoName) {
		if (pseudoName == null) {
			throw new IllegalArgumentException("El nombre del algoritmo de huella digital no puede ser nulo");
		}
		final String upperPseudoName = pseudoName.toUpperCase(Locale.US);
		if (upperPseudoName.equals("SHA")
				|| upperPseudoName.equals("http://www.w3.org/2000/09/xmldsig#sha1".toUpperCase(Locale.US))
				|| upperPseudoName.equals("1.3.14.3.2.26") || upperPseudoName.startsWith("SHA1")
				|| upperPseudoName.startsWith("SHA-1")) {
			return "SHA1";
		}

		if (upperPseudoName.equals("http://www.w3.org/2001/04/xmlenc#sha256".toUpperCase(Locale.US))
				|| upperPseudoName.equals("2.16.840.1.101.3.4.2.1") || upperPseudoName.startsWith("SHA256")
				|| upperPseudoName.startsWith("SHA-256")) {
			return "SHA-256";
		}

		if (upperPseudoName.startsWith("SHA384") || upperPseudoName.equals("2.16.840.1.101.3.4.2.2")
				|| upperPseudoName.startsWith("SHA-384")) {
			return "SHA-384";
		}

		if (upperPseudoName.equals("http://www.w3.org/2001/04/xmlenc#sha512".toUpperCase(Locale.US))
				|| upperPseudoName.equals("2.16.840.1.101.3.4.2.3") || upperPseudoName.startsWith("SHA512")
				|| upperPseudoName.startsWith("SHA-512")) {
			return "SHA-512";
		}

		if (upperPseudoName.equals("http://www.w3.org/2001/04/xmlenc#ripemd160".toUpperCase(Locale.US))
				|| upperPseudoName.startsWith("RIPEMD160") || upperPseudoName.startsWith("RIPEMD-160")) {
			return "RIPEMD160";
		}

		throw new IllegalArgumentException("Algoritmo de huella digital no soportado: " + pseudoName);
	}

	/**
	 * Comprueba si un algoritmo de firma utiliza un algoritmo de huella digital
	 * perteneciente a la familia de algoritmos SHA2.
	 * 
	 * @param algorithm
	 *            Algoritmo de firma.
	 * @return {@code true} cuando el algoritmo es un SHA2, {@code false} en
	 *         caso contrario.
	 */
	public static boolean isSHA2SignatureAlgorithm(final String algorithm) {
		return SIGN_ALGORITHM_SHA256WITHRSA.equals(algorithm) || SIGN_ALGORITHM_SHA384WITHRSA.equals(algorithm)
				|| SIGN_ALGORITHM_SHA512WITHRSA.equals(algorithm);
	}
}