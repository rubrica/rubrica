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

package io.rubrica.sign.ooxml.relprovider;

import java.security.Provider;

/**
 * Proveedor de seguridad para las transformadas de relaci&oacute;n de OOXML.
 */
public class OOXMLProvider extends Provider {

	private static final long serialVersionUID = -8928524984635535408L;

	/** Nombre del proveedor de transformadas de relación OOXML. */
	public static final String RELATIONSHIP_TRANSFORM_PROVIDER_NAME = "OOXMLProvider";

	/** Crea el proveedor de transformadas de relaci&oacute;n OOXML. */
	public OOXMLProvider() {
		super(RELATIONSHIP_TRANSFORM_PROVIDER_NAME, 1.0, "OOXML Security Provider");
		put("TransformService." + RelationshipTransformService.TRANSFORM_URI,
				RelationshipTransformService.class.getName());
		put("TransformService." + RelationshipTransformService.TRANSFORM_URI + " MechanismType", "DOM");
	}
}