/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.rubrica.util;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.LuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.google.zxing.qrcode.QRCodeWriter;
 
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.util.EnumMap;
 
/**
 * Created by gustavo.peiretti on 14/09/2015.
 * http://gustavopeiretti.com/java-generar-codigo-qr/
 * https://github.com/zxing/zxing
 */
public class QRCode {
 
    public static void main(String[] args) {
 
        QRCode qr = new QRCode();
        File file = new File("qrCode.png");
        String text = "Misael Fernández Correa";
 
        try {
 
            java.awt.image.BufferedImage bufferedImage = qr.generateQR(text, 300, 300);
            ImageIO.write(bufferedImage, "png", file);
            System.out.println("QRCode Generated: " + file.getAbsolutePath());
 
            String qrString = qr.decoder(file);
            System.out.println("Text QRCode: " + qrString);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
 
    }
 
    public static BufferedImage generateQR(String text, int h, int w) throws Exception {
        
        java.util.Map<com.google.zxing.EncodeHintType, Object> hints = new EnumMap<>(com.google.zxing.EncodeHintType.class);
        hints.put(com.google.zxing.EncodeHintType.CHARACTER_SET, java.nio.charset.StandardCharsets.ISO_8859_1.name());
        hints.put(com.google.zxing.EncodeHintType.ERROR_CORRECTION, com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.L);
        
        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(text, com.google.zxing.BarcodeFormat.QR_CODE, w, h, hints);

        BufferedImage image = new BufferedImage(matrix.getWidth(), matrix.getHeight(), BufferedImage.TYPE_INT_RGB);
        image.createGraphics();

        Graphics2D graphics = (Graphics2D) image.getGraphics();
        graphics.setColor(Color.WHITE);
        graphics.fillRect(0, 0, matrix.getWidth(), matrix.getHeight());
        graphics.setColor(Color.BLACK);

        for (int i = 0; i < matrix.getWidth(); i++) {
            for (int j = 0; j < matrix.getHeight(); j++) {
                if (matrix.get(i, j)) {
                    graphics.fillRect(i, j, 1, 1);
                }
            }
        }
        return image;
    }
 
    public static String decoder(File file) throws Exception {
 
        FileInputStream inputStream = new FileInputStream(file);
 
        BufferedImage image = ImageIO.read(inputStream);
 
        int width = image.getWidth();
        int height = image.getHeight();
        int[] pixels = new int[width * height];
 
        LuminanceSource source = new BufferedImageLuminanceSource(image);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
 
        // decode the barcode
        QRCodeReader reader = new QRCodeReader();
        Result result = reader.decode(bitmap);
        return new String(result.getText());
    }
}