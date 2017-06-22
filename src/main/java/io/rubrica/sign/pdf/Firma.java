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

package io.rubrica.sign.pdf;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;

import io.rubrica.sign.Falla;

/**
 * Representa una firma digital sobre un documento PDF.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public class Firma {

	private String nombre;
	private boolean firmaCubreTodoDocumento;
	private int revision;

	private X509Certificate certificadoFirmante;
	private Calendar fechaFirma;
	private Certificate[] certificados;
	private boolean selladoTiempoCorrecto;
	private boolean documentoModificado;

	private Falla falla = null;
	private boolean isOscpSignatureValid = false;
	private boolean isOscpRevocationValid = false;

	public Firma(String nombre, boolean firmaCubreTodoDocumento, int revision, X509Certificate certificadoFirmante,
			Calendar fechaFirma, boolean selladoTiempoCorrecto, Certificate[] certificados,
			boolean documentoModificado) {
		this.nombre = nombre;
		this.certificadoFirmante = certificadoFirmante;
		this.firmaCubreTodoDocumento = firmaCubreTodoDocumento;
		this.revision = revision;
		this.fechaFirma = fechaFirma;
		this.selladoTiempoCorrecto = selladoTiempoCorrecto;
		this.certificados = certificados;
		this.documentoModificado = documentoModificado;
	}

	public String getNombre() {
		return nombre;
	}

	public X509Certificate getCertificadoFirmante() {
		return certificadoFirmante;
	}

	/**
	 * Esta firma cubre todo el documento PDF?
	 */
	public boolean firmaCubreTodoDocumento() {
		return firmaCubreTodoDocumento;
	}

	/**
	 * Esta firma es la revision numero?
	 * 
	 * @return
	 */
	public int getRevision() {
		return this.revision;
	}

	/**
	 * En que fecha fue firmado el documento?
	 * 
	 * @return
	 */
	public Calendar getFechaFirma() {
		return fechaFirma;
	}

	/**
	 * Este documento verifica correctamente su sellado de tiempo, si es que lo
	 * tiene.
	 * 
	 * @return
	 */
	public boolean selladoTiempo() {
		return selladoTiempoCorrecto;
	}

	public Certificate[] getCertificados() {
		return certificados;
	}

	public boolean isDocumentoModificado() {
		return documentoModificado;
	}

	public Falla getFalla() {
		return falla;
	}

	public void setFalla(Falla falla) {
		this.falla = falla;
	}

	public boolean tieneFalla() {
		return (falla != null);
	}

	/**
	 * @return the isOscpSignatureValid
	 */
	public boolean isOscpSignatureValid() {
		return isOscpSignatureValid;
	}

	/**
	 * @param isOscpSignatureValid
	 *            the isOscpSignatureValid to set
	 */
	public void setOscpSignatureValid(boolean isOscpSignatureValid) {
		this.isOscpSignatureValid = isOscpSignatureValid;
	}

	/**
	 * @return the isOscpRevocationValid
	 */
	public boolean isOscpRevocationValid() {
		return isOscpRevocationValid;
	}

	/**
	 * @param isOscpRevocationValid
	 *            the isOscpRevocationValid to set
	 */
	public void setOscpRevocationValid(boolean isOscpRevocationValid) {
		this.isOscpRevocationValid = isOscpRevocationValid;
	}

	@Override
	public String toString() {
		return "Firma [nombre=" + nombre + ", firmaCubreTodoDocumento=" + firmaCubreTodoDocumento + ", revision="
				+ revision + ", certificadoFirmante=" + certificadoFirmante + ", fechaFirma=" + fechaFirma
				+ ", certificados=" + Arrays.toString(certificados) + ", selladoTiempoCorrecto=" + selladoTiempoCorrecto
				+ ", documentoModificado=" + documentoModificado + ", falla=" + falla + ", isOscpSignatureValid="
				+ isOscpSignatureValid + ", isOscpRevocationValid=" + isOscpRevocationValid + "]";
	}
}