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

import java.util.ArrayList;
import java.util.List;

import io.rubrica.sign.pdf.Firma;

/**
 * Verificacion de una firma digital.
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
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

	@Override
	public String toString() {
		return "Verificacion [totalRevisiones=" + totalRevisiones + ", firmas=" + firmas + "]";
	}
}