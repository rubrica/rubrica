/*
 * Copyright (c) 2009-2013 Rubrica.ec
 * 
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

package ec.rubrica.keystore;

import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Tratamos los alias repetidos, situacion problematica afectada por el bug
 * http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6483657 Este solo se da
 * con SunMSCAPI
 * 
 * @author Ricardo Arguello <ricardo@rubrica.ec>
 */
public class KeyStoreUtilities {

	private static final Logger log = Logger.getLogger(KeyStoreUtilities.class.getName());

	public static boolean tieneAliasRepetidos(KeyStore keyStore) {
		try {
			ArrayList<String> aliases = Collections.list(keyStore.aliases());
			HashSet<String> uniqAliases = new HashSet<String>(aliases);
			return (aliases.size() > uniqAliases.size());
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * For WINDOWS-MY keystore fixes problem with non-unique aliases
	 * 
	 * @param keyStore
	 */
	@SuppressWarnings("unchecked")
	public static void fixAliases(final KeyStore keyStore) {
		Field field;
		KeyStoreSpi keyStoreVeritable;
		final Set<String> tmpAliases = new HashSet<String>();
		try {
			field = keyStore.getClass().getDeclaredField("keyStoreSpi");
			field.setAccessible(true);
			keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

			if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
				Collection<Object> entries;
				String alias, hashCode;
				X509Certificate[] certificates;
				field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
				field.setAccessible(true);
				entries = (Collection<Object>) field.get(keyStoreVeritable);

				for (Object entry : entries) {
					field = entry.getClass().getDeclaredField("certChain");
					field.setAccessible(true);
					certificates = (X509Certificate[]) field.get(entry);

					hashCode = Integer.toString(certificates[0].hashCode());

					field = entry.getClass().getDeclaredField("alias");
					field.setAccessible(true);
					alias = (String) field.get(entry);
					String tmpAlias = alias;
					int i = 0;
					while (tmpAliases.contains(tmpAlias)) {
						i++;
						tmpAlias = alias + "-" + i;
					}
					tmpAliases.add(tmpAlias);
					if (!alias.equals(hashCode)) {
						field.set(entry, tmpAlias);
					}
				}
			}
		} catch (Exception e) {
			log.severe(e.getMessage());
		}
	}

	public static List<Alias> getSigningAliases(final KeyStore keyStore) {
		try {
			Enumeration<String> aliases = keyStore.aliases();
			List<Alias> aliasList = new ArrayList<Alias>();

			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

				if (certificate != null) {
					String name = certificate.getSubjectDN().getName();

					boolean[] keyUsage = certificate.getKeyUsage();

					if (keyUsage != null && keyUsage[0]) {
						aliasList.add(new Alias(alias, name));
					}
				}
			}

			return aliasList;
		} catch (KeyStoreException e) {
			throw new IllegalStateException(e);
		}
	}
}