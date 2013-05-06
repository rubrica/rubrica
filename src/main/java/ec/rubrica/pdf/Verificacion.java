/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.pdf;

import java.util.ArrayList;
import java.util.List;

/**
 * Verificacion de una firma digital.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class Verificacion {

	private int totalRevisiones;
	private List<Firma> firmas;

	public Verificacion(int totalRevisiones) {
		this.setTotalRevisiones(totalRevisiones);
		this.firmas = new ArrayList<Firma>();
	}

	public Verificacion(int totalRevisiones, List<Firma> firmas) {
		this.setTotalRevisiones(totalRevisiones);
		this.firmas = firmas;
	}

	/**
	 * @return the totalRevisiones
	 */
	public int getTotalRevisiones() {
		return totalRevisiones;
	}

	/**
	 * @param totalRevisiones
	 *            the totalRevisiones to set
	 */
	public void setTotalRevisiones(int totalRevisiones) {
		this.totalRevisiones = totalRevisiones;
	}

	public List<Firma> getFirmas() {
		return firmas;
	}

	public void setFirmas(List<Firma> firmas) {
		this.firmas = firmas;
	}

	public void addFirma(Firma firma) {
		firmas.add(firma);
	}
}