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
 * Certificado de Persona Juridica, Representante Legal o Miembro de empresa:
 * son certificados que identifican al suscriptor como una persona juridica de
 * derecho publico o privado a traves de su representante legal o de las
 * personas que actuen en su representacion, quienes seran responsables en tal
 * calidad de todo lo que firmen dentro del ambito de su competencia y limites
 * de uso que correspondan.
 *
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 */
public interface CertificadoPersonaJuridica {

	/**
	 * @return
	 */
	String getRazonSocial();

	/**
	 * RUC (si no tiene queda en blanco)
	 */
	String getRuc();

	/**
	 * Cedula o Pasaporte del suscriptor
	 */
	String getCedulaPasaporte();

	/**
	 * Nombre(s) del suscriptor
	 */
	String getNombres();

	/**
	 * Primer apellido del suscriptor
	 */
	String getPrimerApellido();

	/**
	 * Segundo apellido del suscriptor (si no tiene queda en blanco)
	 */
	String getSegundoApellido();

	/**
	 * Cargo
	 */
	String getCargo();

	/**
	 * Direccion
	 */
	String getDireccion();

	/**
	 * Telefono
	 */
	String getTelefono();

	/**
	 * Telefono
	 */
	String getCiudad();

	/**
	 * Pais
	 */
	String getPais();
}