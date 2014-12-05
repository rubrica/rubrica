package ec.rubrica.util;

import com.itextpdf.text.Rectangle;

public class RectanguloParaFirmar {

	public static final int ANCHO_RECTANGULO_FIRMA = 108;
	public static final int ALTO_RECTANGULO_FIRMA = 32;

	public static Rectangle obtenerRectangulo(Rectangle dimensionHoja, float posicionUnitariaX,
			float posicionUnitariaY) {
		float lowerLeftX = dimensionHoja.getWidth()*posicionUnitariaX - ANCHO_RECTANGULO_FIRMA/2;
		float lowerLeftY = dimensionHoja.getHeight()*posicionUnitariaY - ALTO_RECTANGULO_FIRMA/2;
		float upperLeftX = dimensionHoja.getWidth()*posicionUnitariaX + ANCHO_RECTANGULO_FIRMA/2;
		float upperLeftY = dimensionHoja.getHeight()*posicionUnitariaY + ALTO_RECTANGULO_FIRMA/2;
		return new Rectangle(lowerLeftX, lowerLeftY, upperLeftX, upperLeftY);
	}

}
