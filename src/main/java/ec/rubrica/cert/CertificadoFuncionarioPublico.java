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
 * Certificado que identifica al suscriptor como funcionario o servidor publico,
 * quien actuara a titulo de la Institucion publica que representa y sera
 * responsable de todo lo que firme electronicamente dentro del ambito de su
 * actividad y limites de uso que correspondan.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public interface CertificadoFuncionarioPublico {

	/**
	 * Cedula o Pasaporte del funcionario publico
	 */
	String getCedulaPasaporte();

	/**
	 * Nombre(s) del funcionario publico
	 */
	String getNombres();

	/**
	 * Primer apellido del funcionario publico
	 */
	String getPrimerApellido();

	/**
	 * Segundo apellido del funcionario publico (si no tiene queda en blanco)
	 */
	String getSegundoApellido();

	/**
	 * Cargo
	 */
	String getCargo();

	/**
	 * Institucion
	 */
	String getInstitucion();

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

	/**
	 * RUC de la Institucion
	 */
	String getRuc();

	/**
	 * Razon Social
	 */
	String getRazonSocial();
}