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

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

/** Resultado de la validaci&oacute;n de un certificado X.509. */
public enum ValidationResult {

	/** V&aacute;lido. */
	VALID(0),
	/** No compatible X.509 o corrupto. */
	CORRUPT(1),
	/** No se soporta la CA de expedici&oacute;n. */
	CA_NOT_SUPPORTED(2),
	/** Aun no v&aacute;lido. */
	NOT_YET_VALID(3),
	/** Caducado. */
	EXPIRED(4),
	/** Revocado. */
	REVOKED(5),
	/** Desconocido. */
	UNKNOWN(6),
	/** Error interno, de red o del servidor OCSP. */
	SERVER_ERROR(7),
	/** No autorizado. */
	UNAUTHORIZED(8),
	/** Petici&oacute;n OCSP mal formada. */
	MALFORMED_REQUEST(9),
	/** La petici&oacute;n OCSP no est&aacute; firmada. */
	SIG_REQUIRED(10),
	/** No se ha podido descargar la lista de certificados revocados. */
	CANNOT_DOWNLOAD_CRL(11);

	private static final int CODE_VALID = 0;
	private static final int CODE_CORRUPT = 1;
	private static final int CODE_CA_NOT_SUPPORTED = 2;
	private static final int CODE_NOT_YET_VALID = 3;
	private static final int CODE_EXPIRED = 4;
	private static final int CODE_REVOKED = 5;
	private static final int CODE_UNKNOWN = 6;
	private static final int CODE_SERVER_ERROR = 7;
	private static final int CODE_UNAUTHORIZED = 8;
	private static final int CODE_MALFORMED_REQUEST = 9;
	private static final int CODE_SIG_REQUIRED = 10;
	private static final int CODE_CANNOT_DOWNLOAD_CRL = 11;

	private final int resultCode;

	private ValidationResult(int code) {
		if (code < CODE_VALID || code > CODE_CANNOT_DOWNLOAD_CRL) {
			throw new IllegalArgumentException("El codigo de resultado debe estar comprendido entre 0 y 11: " + code);
		}
		this.resultCode = code;
	}

	/**
	 * Obtiene la representaci&oacute;n JSON del resultado de la
	 * validaci&oacute;n.
	 * 
	 * @return Representaci&oacute;n JSON del resultado de la validaci&oacute;n
	 */
	public String toJsonString() {
		return new StringBuilder().append("{\n").append("  \"result\": \"").append(isValid() ? "OK" : "KO")
				.append("\",\n").append("  \"reason\": \"").append(toString()).append("\"\n").append("}").toString();
	}

	/**
	 * Indica si el resultado corresponde a un certificado X.509v3
	 * v&aacute;lido, dentro de su periodo de validez y no revocado).
	 * 
	 * @return <code>true</code> si corresponde a un certificado X.509v3
	 *         v&aacute;lido, <code>false</code> en caso contrario
	 */
	public boolean isValid() {
		return this.resultCode == CODE_VALID;
	}

	/**
	 * Lanza las excepciones apropiadas en caso de que el certificado no sea
	 * v&aacute;lido.
	 * 
	 * @throws CertificateException
	 *             Cuando el certificado no es v&aacute;lido.
	 */
	public void check() throws CertificateException {
		switch (this.resultCode) {
		case CODE_VALID:
			return;
		case CODE_CORRUPT:
			throw new CertificateEncodingException();
		case CODE_CA_NOT_SUPPORTED:
			throw new CertificateException("El certificado no es de una CA soportada"); //$NON-NLS-1$
		case CODE_NOT_YET_VALID:
			throw new CertificateNotYetValidException();
		case CODE_EXPIRED:
			throw new CertificateExpiredException();
		case CODE_REVOKED:
			throw new CertificateException("Certificado revocado"); //$NON-NLS-1$
		case CODE_UNKNOWN:
			throw new CertificateException("Validez del certificado desconocida"); //$NON-NLS-1$
		case CODE_SERVER_ERROR:
			throw new CertificateException("Error interno o del servidor al validar el certificado"); //$NON-NLS-1$
		case CODE_UNAUTHORIZED:
			throw new CertificateException("No autorizado"); //$NON-NLS-1$
		case CODE_MALFORMED_REQUEST:
			throw new CertificateException("Peticion OCSP mal formada"); //$NON-NLS-1$
		case CODE_SIG_REQUIRED:
			throw new CertificateException("La peticion OCSP no esta firmada"); //$NON-NLS-1$
		case CODE_CANNOT_DOWNLOAD_CRL:
			throw new CertificateException("No se ha podido descargar la lista de certificados revocados"); //$NON-NLS-1$
		default:
			throw new IllegalStateException(
					"El codigo de resultado debe estar comprendido entre 0 y 11: " + this.resultCode //$NON-NLS-1$
			);
		}
	}
}