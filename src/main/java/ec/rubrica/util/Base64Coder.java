/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.util;

import javax.xml.bind.DatatypeConverter;

/**
 * Clase utilitaria que ofrece metodos para codificar y decodificar cadenas de
 * texto desde y hacia Base 64.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class Base64Coder {

	private Base64Coder() {
	}

	/**
	 * Codifica un arreglo de bytes a una cadena de texto en base64.
	 * 
	 * @param unencoded
	 *            el arreglo de byes que sera codificado
	 * @return la cadena de texto codificada
	 */
	public static String encode(byte[] unencoded) {
		if (unencoded == null) {
			return null;
		} else if (unencoded.length == 0) {
			return new String();
		}
		return DatatypeConverter.printBase64Binary(unencoded);
	}

	/**
	 * Codifica una cadena de texto en base 64. Retorna <code>null</code> isi la
	 * cadena de texto es <code>null</code>.
	 * 
	 * @param unencoded
	 * @return
	 */
	public static String encode(String unencoded) {
		if (isEmpty(unencoded)) {
			return unencoded;
		}
		return encode(unencoded.getBytes());
	}

	/**
	 * Decodifica un arreglo de bytes en base 64.
	 * 
	 * @param encoded
	 *            la cadena de texto codificada como base64
	 * @return la cadena de texto decodificada
	 */
	public static String decode(byte[] encoded) {
		if (encoded == null || encoded.length == 0) {
			return new String();
		}
		return decode(new String(encoded));
	}

	/**
	 * Decodifica la cadena de texto en base 64 enviada. Retorna
	 * <code>null</code> si la cadena de texto enviada es <code>null</code>.
	 * 
	 * @param encoded
	 *            la cadena de texto codificada como base64
	 * @return la cadena de texto decodificada
	 */
	public static String decode(String encoded) {
		if (isEmpty(encoded)) {
			return encoded;
		}
		byte[] encodedBytes = DatatypeConverter.parseBase64Binary(encoded);
		return new String(encodedBytes);
	}

	/**
	 * Verifica si una cadena de texto esta vacia: Si es <code>null</code> o
	 * contiene solamente espacios.
	 * 
	 * @param string
	 * @return
	 */
	private static boolean isEmpty(String string) {
		return string == null || string.trim().isEmpty();
	}
}