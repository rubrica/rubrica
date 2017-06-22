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

public class SignValidity {

	public enum SIGN_DETAIL_TYPE {
		OK, FAIL
	}

	/**
	 * Errores que invalidan una firma o impiden conocer si es v&aacute;lida o
	 * no.
	 */
	public enum VALIDITY_ERROR {
		/**
		 * Cuando no se puede comprobar la validez por no tener los datos
		 * firmados.
		 */
		NO_DATA,
		/**
		 * Cuando la informacion contenida en la firma no sea consistente
		 * (certificados corruptos, etc.).
		 */
		CORRUPTED_SIGN,
		/** Cuando la firma no se corresponde con los datos firmados. */
		NO_MATCH_DATA,
		/** Cuando no se encuentra la firma dentro del documento. */
		NO_SIGN,
		/**
		 * Cuando no se puede extraer un certificado o este no es v&aacute;lido.
		 */
		CERTIFICATE_PROBLEM,
		/** Cuando existe un certificado de firma caducado. */
		CERTIFICATE_EXPIRED,
		/**
		 * Cuando existe un certificado de firma que aun no es v&aacute;lido.
		 */
		CERTIFICATE_NOT_VALID_YET,
		/**
		 * Cuando la firma contiene un algoritmo no reconocido o no soportado.
		 */
		ALGORITHM_NOT_SUPPORTED,
		/** Cuando el emisor del certificado no es v&aacute;lido. */
		CA_NOT_SUPPORTED,
		/**
		 * Cuando existe alg&uacute;n problema con las CRLs incrustadas en la
		 * firma.
		 */
		CRL_PROBLEM,
		/** Cuando se trata de una firma PDF. */
		PDF_UNKOWN_VALIDITY,
		/** Cuando se trata de una firma OOXML. */
		OOXML_UNKOWN_VALIDITY,
		/** Cuando se trata de una firma ODF. */
		ODF_UNKOWN_VALIDITY,
		/**
		 * Cuando la firma es inv&aacute;lida pero no se sabe la raz&oacute;n.
		 */
		UNKOWN_ERROR,
		/**
		 * Cuando los datos proporcionado no sean ning&uacute;n tipo de firma
		 * reconocida.
		 */
		UNKOWN_SIGNATURE_FORMAT
	}

	/** Validez de la firma. */
	private final SIGN_DETAIL_TYPE validity;

	/** Error que invalida la firma o hace que la validez sea desconocida. */
	private final VALIDITY_ERROR error;

	/**
	 * Identifica la validez de una firma.
	 * 
	 * @param type
	 *            Validez de la firma.
	 * @param error
	 *            Error que invalida o impide comprobar la firma.
	 */
	public SignValidity(final SIGN_DETAIL_TYPE type, final VALIDITY_ERROR error) {
		this.validity = type;
		this.error = error;
	}

	/**
	 * Recupera la validez de la firma.
	 * 
	 * @return Validez de la firma.
	 */
	public SIGN_DETAIL_TYPE getValidity() {
		return this.validity;
	}

	/**
	 * Recupera el error que invalida la firma. Si no existe ning&uacute;n error
	 * o este es desconocido, se devolver&aacute; {@code null}.
	 * 
	 * @return Error que invalida la firma o impide comprobar su validez.
	 */
	public VALIDITY_ERROR getError() {
		return this.error;
	}

}