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

/**
 * Valida una firma del tipo del validador instanciado.
 */
public interface Validator {

	/**
	 * Valida una firma del tipo del validador instanciado.
	 * 
	 * @param sign
	 *            Firma a validar
	 * @return Validez de la firma.
	 * @throws IOException
	 *             Fallo durante la validaci&oacute;n de la firma.
	 */
	SignValidity validate(final byte[] sign) throws IOException;
}