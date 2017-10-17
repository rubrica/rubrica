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

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Properties;

import io.rubrica.core.RubricaException;

/**
 * Permite la firma digital de documentos.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public interface Signer {

	/**
	 * Firma digitalmente un archivo.
	 * 
	 * @param data
	 *            Archivo a firmar
	 * @param algorithm
	 *            Algoritmo a usar para la firma
	 * @param key
	 *            Clave privada a usar para firmar
	 * @param certChain
	 *            Cadena de certificados del firmante
	 * @param extraParams
	 *            Parámetros adicionales para la firma
	 * @return Contenido firmado
	 * @throws RubricaException
	 *             Cuando ocurre cualquier problema durante el proceso
	 * @throws IOException
	 *             Cuando ocurren problemas relacionados con la lectura de los
	 *             datos
	 */
	byte[] sign(byte[] data, String algorithm, PrivateKey key, Certificate[] certChain, Properties extraParams)
			throws RubricaException, IOException;

	List<SignInfo> getSigners(byte[] sign) throws InvalidFormatException, IOException;
}