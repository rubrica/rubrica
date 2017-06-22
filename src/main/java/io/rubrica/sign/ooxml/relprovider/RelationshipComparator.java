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

package io.rubrica.sign.ooxml.relprovider;

import java.util.Comparator;

import org.w3c.dom.Element;

/**
 * Comparator for Relationship DOM elements.
 */
class RelationshipComparator implements Comparator<Element> {

	@Override
	public int compare(final Element element1, final Element element2) {
		final String id1 = element1.getAttribute("Id");
		final String id2 = element2.getAttribute("Id");
		return id1.compareTo(id2);
	}
}