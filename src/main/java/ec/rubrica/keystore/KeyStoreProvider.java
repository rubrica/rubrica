/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.keystore;

import java.security.KeyStore;
import java.security.KeyStoreException;

/**
 * Obtiene un KeyStore.
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public interface KeyStoreProvider {

	KeyStore getKeystore() throws KeyStoreException;

	KeyStore getKeystore(char[] password) throws KeyStoreException;
}