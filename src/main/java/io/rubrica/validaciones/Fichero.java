/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package io.rubrica.validaciones;

/**
 *
 * @author mfernandez
 */
public class Fichero {

    public static String ruta() throws Exception{
        String ruta = "";
        javax.swing.JFileChooser elegirRuta = new javax.swing.JFileChooser(new java.io.File(System.getProperty("user.home")));
        elegirRuta.setAcceptAllFileFilterUsed(false);
        elegirRuta.setFileFilter(new io.rubrica.validaciones.FiltrarArchivosPdf());
        
        int opcionElegida = elegirRuta.showSaveDialog(null);
        if (opcionElegida == javax.swing.JFileChooser.APPROVE_OPTION) {
            java.io.File file = new java.io.File(elegirRuta.getSelectedFile()+elegirRuta.getFileFilter().toString());
            if (file.exists() && file.isFile()) {
                if (javax.swing.JOptionPane.YES_OPTION == javax.swing.JOptionPane.showConfirmDialog(
                        null, "El archivo será sobrescrito. Desea continuar?", "Confirmacion", javax.swing.JOptionPane.YES_NO_OPTION)) {
                    file.delete();
                    ruta = file.toString();
                }
            } else {
                if (!file.isDirectory()) {
                    ruta = file.toString();
                }
            }
        }
        return ruta;
    }
    public static String ruta(java.io.File archivo, String extencion) throws Exception{
        String ruta = "";
        javax.swing.JFileChooser elegirRuta = new javax.swing.JFileChooser(new java.io.File(System.getProperty("user.home")));
        elegirRuta.setSelectedFile(archivo);
        
//        elegirRuta.setCurrentDirectory(java.io.File.pathSeparator);
        elegirRuta.setAcceptAllFileFilterUsed(false);
        if (extencion.equals(".pdf"))
            elegirRuta.setFileFilter(new io.rubrica.validaciones.FiltrarArchivosPdf());
        int opcionElegida = elegirRuta.showSaveDialog(null);
        if (opcionElegida == javax.swing.JFileChooser.APPROVE_OPTION) {
            String archivoEscogido = elegirRuta.getSelectedFile()+elegirRuta.getFileFilter().toString();
            if(archivoEscogido.indexOf(extencion, archivoEscogido.indexOf(extencion)+1)>-1)
               archivoEscogido=archivoEscogido.substring(0, archivoEscogido.indexOf(extencion,archivoEscogido.indexOf(extencion)+1));
            
            java.io.File file = new java.io.File(archivoEscogido);
            
            if (file.exists() && file.isFile()) {
                if (javax.swing.JOptionPane.YES_OPTION == javax.swing.JOptionPane.showConfirmDialog(
                        null, "El archivo será sobrescrito. Desea continuar?", "Confirmacion", javax.swing.JOptionPane.YES_NO_OPTION)) {
                    file.delete();
                    ruta = file.toString();
                }
            } else {
                if (!file.isDirectory()) {
                    ruta = file.toString();
                }
            }
        }
        return ruta;
    }

    public static String rutaAbrir() throws Exception{
        String ruta = "";
        javax.swing.JFileChooser elegirRuta = new javax.swing.JFileChooser(new java.io.File(System.getProperty("user.home")));
        elegirRuta.setAcceptAllFileFilterUsed(false);
        int opcionElegida = elegirRuta.showOpenDialog(null);
        if (opcionElegida == javax.swing.JFileChooser.APPROVE_OPTION) {
            java.io.File file = new java.io.File(elegirRuta.getSelectedFile().toString());
            if (file.exists() && file.isFile()) {
                ruta = file.toString();
            } else {
                if (!file.isDirectory()) {
                    ruta = file.toString();
                }
            }
        }
        return ruta;
    }
    
    public static void guardarFichero(String rutaFichero, java.util.List<String> lista) throws java.io.IOException{
        // instancio objetos de escritura
        java.io.FileWriter fichero = null;
        java.io.PrintWriter pw = null;
        try {
            // asigno nombre de fichero, mantengo la nomenclatura
            fichero = new java.io.FileWriter(rutaFichero);
            // asigno PrintWriter a fichero
            pw = new java.io.PrintWriter(fichero);
            // escribo los parametros
            for(int i=0; i<lista.size(); i++){
                pw.print(lista.get(i));
            }
            // vuelco la memoria al disco duro
            pw.flush();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // cierro los canales de escritura
            fichero.close();
            pw.close();
        }// end try
    }// end Guardar
    
    public static java.util.List<String> leerFichero(String rutaFichero) throws java.io.IOException{
        java.util.List<String> lista = new java.util.ArrayList();
        java.io.File fichero = null;
        java.io.FileReader fr = null;
        java.io.BufferedReader br = null;

        try {
            // Apertura del fichero y creacion de BufferedReader para poder
            // hacer una lectura comoda (disponer del metodo readLine()).
            fichero = new java.io.File (rutaFichero);
            fr = new java.io.FileReader (fichero);
            br = new java.io.BufferedReader(fr);

            // Lectura del fichero
            String linea;
            while((linea=br.readLine())!=null)
                lista.add(linea);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // En el finally cerramos el fichero, para asegurarnos
            // que se cierra tanto si todo va bien como si salta 
            // una excepcion.
            try{
                if(null != fr)
                    fr.close();
            }catch (Exception e2){
                e2.printStackTrace();
            }
            return lista;
        }// end try
    }// end Guardar
    
    public static java.util.List<String> separarLinea(String linea) {
        java.util.List<String> columnas = new java.util.ArrayList();
        try {
            //Delimitador
            java.util.StringTokenizer st = new java.util.StringTokenizer(linea, "¬");

            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                columnas.add(token);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return columnas;
    }

    public static void main(String[] args) {
        java.util.List<String> lista = new java.util.ArrayList();
        try {
//            lista.add(new String("Misael\t\n".getBytes("UTF-8"),"ISO-8859-1"));
//            lista.add(new String("Fernández\r\n".getBytes("ASCII"),"ISO-8859-1"));//windows//
//            lista.add(new String("Misael\n".getBytes("ASCII"),"ISO-8859-1"));//windows
            guardarFichero("/home/desarrollo/fichero.txt", lista);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void abrirFichero(String rutaFichero){
        //abrir archivo
        java.io.File archivo = new java.io.File(rutaFichero);
        if(java.awt.Desktop.isDesktopSupported()==true) {
            java.awt.Desktop desktop = java.awt.Desktop.getDesktop();
            try {
                if(archivo.exists()==true)
                    desktop.open(archivo);
                else
                    javax.swing.JOptionPane.showMessageDialog(null, "No se encontrar el archivo: " + archivo.getAbsolutePath(), "Aviso", javax.swing.JOptionPane.WARNING_MESSAGE);
            }catch (java.io.IOException e) {}
        }else
            javax.swing.JOptionPane.showMessageDialog(null, "No se puede ejecutar el comando de apertura en este sistema operativo", "Aviso", javax.swing.JOptionPane.WARNING_MESSAGE);
    }

    /**
     * Busca todos los ficheros que cumplen la máscara que se le pasa y los
     * mete en la listaFicheros que se le pasa.
     *
     * @param pathInicial Path inicial de búsqueda. Debe ser un directorio que
     * exista y con permisos de lectura.
     * @param mascara Una máscara válida para la clase Pattern de java.
     * @param listaFicheros Una lista de ficheros a la que se añadirán los File
     * que cumplan la máscara. No puede ser null. El método no la vacía.
     * @param busquedaRecursiva Si la búsqueda debe ser recursiva en todos los
     * subdirectorios por debajo del pathInicial.
     */
    public static void ficheros(String pathInicial, String mascara,
            java.util.LinkedList<java.io.File> listaFicheros, boolean busquedaRecursiva)
    {
        java.io.File directorioInicial = new java.io.File(pathInicial);
        if (directorioInicial.isDirectory())
        {
            java.io.File[] ficheros = directorioInicial.listFiles();
            for (int i = 0; i < ficheros.length; i++)
            {
                if (ficheros[i].isDirectory() && busquedaRecursiva)
                    ficheros(ficheros[i].getAbsolutePath(), mascara,
                            listaFicheros, busquedaRecursiva);
                else if (java.util.regex.Pattern.matches(mascara, ficheros[i].getName()))
                    listaFicheros.add(ficheros[i]);
            }
        }
    }

    /**
     * Se le pasa una máscara de fichero típica de ficheros con * e ? y
     * devuelve la cadena regex que entiende la clase Pattern.
     * @param mascara Un String que no sea null.
     * @return Una máscara regex válida para Pattern.
     */
    private static String regex(String mascara)
    {
        mascara = mascara.replace(".", "\\.");
        mascara = mascara.replace("*", ".*");
        mascara = mascara.replace("?",".");
        return mascara;
    }

    public static void eliminarFicheros(String ruta, String ficheroBuscar)
    {
        java.util.LinkedList<java.io.File> ficheros = new java.util.LinkedList<java.io.File>();
        ficheros(ruta, regex(ficheroBuscar), ficheros, true);
//                regex("*.java"), ficherosJava, true);
        for (int i = 0; i < ficheros.size(); i++){
            System.out.println(ficheros.get(i).getAbsolutePath().toString());
            java.io.File file = new java.io.File(ficheros.get(i).getAbsolutePath().toString());
            file.delete();
        }
    }

    public static  String rutaDirectorio() throws Exception{
        String rutaFichero="";
        //nos creamos el JFileChooser
        javax.swing.JFileChooser fileChooser = new javax.swing.JFileChooser();
        fileChooser.setFileSelectionMode(javax.swing.JFileChooser.FILES_AND_DIRECTORIES );
        fileChooser.setDialogType(javax.swing.JFileChooser.SAVE_DIALOG);
        //int result = fileChooser.showOpenDialog( this );
        int seleccion = fileChooser.showOpenDialog(fileChooser);
        //si la opción es la correcta
        if (seleccion == javax.swing.JFileChooser.APPROVE_OPTION){
            java.io.File fichero = fileChooser.getSelectedFile();
            //obtenemos la ruta
            rutaFichero=fichero.getAbsolutePath();
        }
        return rutaFichero;
    }
    
    public void verificarCrearDirectorio(){
        String DIRECTORIO_TEMPORAL="tmp";
        String directorioComprobantesAutorizados ="tmp/comprobantesAutorizados";
        String directorioComprobantesNoAutorizados = "tmp/comprobantesNoAutorizados";
        String directorioComprobantesGenerados = "tmp/comprobantesGenerados";
        String directorioComprobantesFirmados = "tmp/comprobantesFirmados";
        java.io.File directorio = new  java.io.File(DIRECTORIO_TEMPORAL);
        if(!directorio.exists()){
                directorio.mkdir();
                directorio = new  java.io.File (directorioComprobantesAutorizados);
                if(!directorio.exists())
                    directorio.mkdir();
                directorio = new  java.io.File (directorioComprobantesNoAutorizados);
                if(!directorio.exists())
                    directorio.mkdir();
                directorio = new  java.io.File (directorioComprobantesGenerados);
                if(!directorio.exists())
                    directorio.mkdir();
                directorio = new  java.io.File (directorioComprobantesFirmados);
                if(!directorio.exists())
                    directorio.mkdir();
        }
    }
}
