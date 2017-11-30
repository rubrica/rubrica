package io.rubrica.validaciones;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author mfernandez
 */
public class Documento {
    //////Leer archivo
    public static byte[] readFully(InputStream stream) throws IOException
    {
        byte[] buffer = new byte[8192];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        int bytesRead;
        while ((bytesRead = stream.read(buffer)) != -1)
        {
            baos.write(buffer, 0, bytesRead);
        }
        return baos.toByteArray();
    }
    //////Cargar archivo
    public static byte[] loadFile(String sourcePath) throws IOException
    {
        InputStream inputStream = null;
        try 
        {
            inputStream = new FileInputStream(sourcePath);
            return readFully(inputStream);
        } 
        finally
        {
            if (inputStream != null)
            {
                inputStream.close();
            }
        }
    }
}
