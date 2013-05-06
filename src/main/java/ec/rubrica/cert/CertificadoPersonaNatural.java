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
 * Certificado que identifica al suscriptos como una persona natural o fisica, y
 * sera responsable a titulo personal de todo lo que firme electronicamente,
 * dentro del ambito de su actividad y limites de uso que correspondan.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
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
