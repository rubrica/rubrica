package ec.rubrica.test.pdf;

import junit.framework.Assert;

import org.junit.Test;

import com.itextpdf.text.Rectangle;

import ec.rubrica.util.RectanguloParaFirmar;

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
