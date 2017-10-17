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

package io.rubrica.certificate.ec;

/**
 * Certificado que identifica al suscriptos como una persona natural o fisica, y
 * sera responsable a titulo personal de todo lo que firme electronicamente,
 * dentro del ambito de su actividad y limites de uso que correspondan.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public interface CertificadoPersonaNatural {

	/**
	 * Cedula o Pasaporte
	 */
	String getCedulaPasaporte();

	/**
	 * Nombre(s)
	 */
	String getNombres();

	/**
	 * Primer apellido
	 */
	String getPrimerApellido();

	/**
	 * Segundo apellido (si no tiene queda en blanco)
	 */
	String getSegundoApellido();

	/**
	 * Direccion
	 */
	String getDireccion();

	/**
	 * Telefono
	 */
	String getTelefono();

	/**
	 * Ciudad
	 */
	String getCiudad();

	/**
	 * Pais
	 */
	String getPais();

	/**
	 * RUC (si no tiene queda en blanco)
	 */
	String getRuc();
}
