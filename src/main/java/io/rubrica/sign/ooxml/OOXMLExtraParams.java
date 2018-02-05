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

package io.rubrica.sign.ooxml;

class OOXMLExtraParams {

	/** Ciudad en la que se realiza la firma. */
	static final String SIGNATURE_PRODUCTION_CITY = "signatureProductionCity";

	/** Provincia en la que se realiza la firma. */
	static final String SIGNATURE_PRODUCTION_PROVINCE = "signatureProductionProvince";

	/** C&oacute;digo postal en el que se realiza la firma. */
	static final String SIGNATURE_PRODUCTION_POSTAL_CODE = "signatureProductionPostalCode";

	/** Pa&iacute;s en el que se realiza la firma. */
	static final String SIGNATURE_PRODUCTION_COUNTRY = "signatureProductionCountry";

	/** Cargo atribuido para el firmante. */
	static final String SIGNER_CLAIMED_ROLES = "signerClaimedRoles";

	/** Comentarios sobre la firma (normalmente la raz&oacute;n de la firma). */
	static final String SIGNATURE_COMMENTS = "signatureComments";

	/**
	 * Primera l&iacute;nea de la direcci&oacute;n en la que se ha realizado la
	 * firma.
	 */
	static final String SIGNATURE_ADDRESS1 = "signatureAddress1";

	/**
	 * Segunda l&iacute;nea de la direcci&oacute;n en la que se ha realizado la
	 * firma.
	 */
	static final String SIGNATURE_ADDRESS2 = "signatureAddress2";
}