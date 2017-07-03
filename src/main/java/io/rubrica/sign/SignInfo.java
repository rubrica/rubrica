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

import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Date;

import io.rubrica.util.Utils;

/**
 * Representa una firma digital sobre un documento PDF.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class SignInfo {

	/** Cadena de certificaci&oacute;n. */
	private X509Certificate[] certs;

	/** Algoritmo de firma. */
	private String signAlgorithm = null;

	/** Momento de la firma segundo el dispositivo que la realiz&oacute;. */
	private Date signingTime;

	/** Cadena binaria con el PKCS#1 de la firma individual. */
	private byte[] pkcs1 = null;

	public SignInfo(X509Certificate[] chainCert, Date signingTime) {
		if (chainCert == null || chainCert.length == 0 || chainCert[0] == null) {
			throw new IllegalArgumentException("No se ha introducido la cadena de certificacion");
		}

		this.certs = chainCert.clone();
		this.signingTime = signingTime;
	}

	/**
	 * Obtiene el certificado (con su cadena de confianza) de la firma.
	 * 
	 * @return Certificado (con su cadena de confianza) de la firma
	 */
	public X509Certificate[] getCerts() {
		return this.certs == null ? null : this.certs.clone();
	}

	/**
	 * Obtiene la fecha de la firma.
	 * 
	 * @return Fecha de la firma
	 */
	public Date getSigningTime() {
		return this.signingTime;
	}

	/**
	 * Obtiene el algoritmo de firma.
	 * 
	 * @return Algoritmo de firma
	 */
	public String getSignAlgorithm() {
		return this.signAlgorithm;
	}

	/**
	 * Establece el algoritmo de firma
	 * 
	 * @param algorithm
	 *            Algoritmo de firma
	 */
	public void setSignAlgorithm(String algorithm) {
		this.signAlgorithm = algorithm;
	}

	/**
	 * Recupera el PKCS#1 de la firma en cuesti&oacute;n. Devuelve {@code null}
	 * si no se preestablecio.
	 * 
	 * @return PKCS#1 de la firma.
	 */
	public byte[] getPkcs1() {
		return this.pkcs1 == null ? null : this.pkcs1.clone();
	}

	/**
	 * Establece el PKCS#1 de la firma.
	 * 
	 * @param pkcs1
	 *            PKCS#1 que gener&oacute; la firma.
	 */
	public void setPkcs1(final byte[] pkcs1) {
		this.pkcs1 = pkcs1 == null ? null : pkcs1.clone();
	}

	@Override
	public String toString() {
		String desc = Utils.getCN(this.certs[0]);
		if (this.signingTime != null) {
			desc += " (" + DateFormat.getDateTimeInstance(DateFormat.DEFAULT, DateFormat.SHORT).format(this.signingTime)
					+ ")";
		}
		return desc;
	}
}