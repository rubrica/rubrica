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

/** Relaci&oacute;n XML seg&uacute;n la normativa OOXML. */
final class Relationship {

	private String id = null;
	private String type = null;
	private String target = null;

	/**
	 * Construye un objeto de relaci&oacute;n OOXML.
	 * 
	 * @param id
	 *            Identificador de la relaci&oacute;n
	 * @param type
	 *            Typo de la relaci&oacute;n
	 * @param target
	 *            Destino de la relaci&oacute;n (objeto relacionado)
	 */
	Relationship(final String id, final String type, final String target) {
		this.id = id;
		this.type = type;
		this.target = target;
	}

	/**
	 * Obtiene el identificador de la relaci&oacute;n.
	 * 
	 * @return Identificador de la relaci&oacute;n
	 */
	String getId() {
		return this.id;
	}

	/**
	 * Obtiene el tipo de la relaci&oacute;n.
	 * 
	 * @return Tipo de la relaci&oacute;n
	 */
	String getType() {
		return this.type;
	}

	/**
	 * Obtiene el destino de la relaci&oacute;n (el objeto relacionado)
	 * 
	 * @return Destino de la relaci&oacute;n (objeto relacionado)
	 */
	String getTarget() {
		return this.target;
	}

	@Override
	public String toString() {
		return "<Relationship Id=\"" + this.id + "\" Type=\"" + this.type + "\" Target=\"" + this.target + "\"/>"; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
	}
}