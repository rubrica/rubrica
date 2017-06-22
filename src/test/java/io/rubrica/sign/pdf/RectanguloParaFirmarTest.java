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

import org.junit.Test;

import com.lowagie.text.Rectangle;

import junit.framework.Assert;

public class RectanguloParaFirmarTest {

	@Test
	public void obtenerRectanguloTest(){
		float posicionUnitariaX = 0.5f;
		float posicionUnitariaY = 0.5f;
		Rectangle dimensionHoja = new Rectangle(1000.0f, 500.0f);
		Rectangle rectangulo = RectanguloParaFirmar.obtenerRectangulo(dimensionHoja, posicionUnitariaX, posicionUnitariaY);
		Assert.assertEquals((float)500 - RectanguloParaFirmar.ANCHO_RECTANGULO_FIRMA/2, rectangulo.getLeft());
		Assert.assertEquals((float)500 + RectanguloParaFirmar.ANCHO_RECTANGULO_FIRMA/2, rectangulo.getRight());
		Assert.assertEquals((float)250 - RectanguloParaFirmar.ALTO_RECTANGULO_FIRMA/2, rectangulo.getBottom());
		Assert.assertEquals((float)250 + RectanguloParaFirmar.ALTO_RECTANGULO_FIRMA/2, rectangulo.getTop());
	}
}
