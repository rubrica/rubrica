/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package io.rubrica.validaciones;

import java.io.File;

import javax.swing.filechooser.FileFilter;

/**
 *
 * @author mfernandez
 */
public class FiltrarArchivosPdf extends FileFilter {
	public boolean accept(File f) {
		if (f.isDirectory()) {
			return true;
		}

		String extension = Extensiones.getExtension(f);
		if (extension != null) {
			if (extension.equals(Extensiones.pdf)) {
				return true;
			} else {
				return false;
			}
		}

		return false;
	}

	// The description of this filter
	public String getDescription() {
		return "Archivos PDF (*.pdf)";
	}

	@Override
	public String toString() {
		return "." + Extensiones.pdf;
	}
}