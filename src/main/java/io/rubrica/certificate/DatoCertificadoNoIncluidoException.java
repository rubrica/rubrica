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

package io.rubrica.certificate;

/**
 * Excepcion que se lanza en caso de que el certificado no incluya un campo.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class DatoCertificadoNoIncluidoException extends RuntimeException {

	private static final long serialVersionUID = 5614921752347842642L;

	public DatoCertificadoNoIncluidoException(String message) {
		super(message);
	}
}