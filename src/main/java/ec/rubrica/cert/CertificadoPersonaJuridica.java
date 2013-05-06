/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.cert;

/**
 * Certificado de Persona Juridica, Representante Legal o Miembro de empresa:
 * son certificados que identifican al suscriptor como una persona juridica de
 * derecho publico o privado a traves de su representante legal o de las
 * personas que actuen en su representacion, quienes seran responsables en tal
 * calidad de todo lo que firmen dentro del ambito de su competencia y limites
 * de uso que correspondan.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
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