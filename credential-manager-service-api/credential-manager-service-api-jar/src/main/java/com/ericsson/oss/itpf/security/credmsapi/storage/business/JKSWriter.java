/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.storage.business;

import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.StorageFormatUtils;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

/**
 * 
 * @author ewagdeb
 * 
 */
public class JKSWriter implements CredentialWriter {

	private static final Logger LOG = LogManager.getLogger(JKSWriter.class);

	/**
     * 
     */
	// private static final org.slf4j.Logger LOG =
	// LoggerFactory.getLogger(JKSWriter.class);
	/**
	 * JKS file Path
	 */
	private String jksFolderPath = "";
	private String jksFilePath = "";

	// keystore type to use (JKS or JCEKS)
	private String storeType = StorageConstants.JKS_STORE_TYPE;

	/**
	 * JKS password
	 */
	private String password = "";

	private JKSWriter() {

	}

	public JKSWriter(final String jksFolderPath, final String jksFilePath,
			final String password, final String storeType) {
		this();
		this.jksFolderPath = jksFolderPath;
		this.jksFilePath = jksFilePath;
		this.password = password;
		if (StorageFormatUtils.isValidStorageConstant(storeType)) {
			this.storeType = storeType;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.ericsson.nms.security.pki.store.CredentialWriter#storeKeyPair(java
	 * .security.Key, java.security.cert.Certificate, java.lang.String)
	 */
	@Override
	public void storeKeyPair(final Key key,
			final Certificate[] certificateChain, final String alias)
			throws StorageException {

		System.out.println("storeKeyPair " + alias + " in " + this.jksFilePath);
		LOG.debug("storeKeyPair " + alias + " in " + this.jksFilePath);

		// Store away the keystore.
		FileOutputStream fos = null;

		try {
			/*
			 * LOG.info(
			 * Logger.getLogMessage(Logger.LOG_INFO_CREATE_START_KEYSTORE),
			 * jksFilePath);
			 */

			final KeyStore ks = this.getKeyStore(this.jksFilePath);
			fos = new FileOutputStream(new File(this.jksFilePath));

			// store new data
			ks.setKeyEntry(alias, key, this.password.toCharArray(),
					certificateChain);
			ks.store(fos, this.password.toCharArray());

			// LOG.info(Logger.getLogMessage(Logger.LOG_INFO_CREATE_END_KEYSTORE),
			// jksFilePath);
			// LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CREATE_KEYSTORE),
			// jksFilePath);

		} catch (final Exception ex) {
			LOG.error(ErrorMsg.API_ERROR_STORAGE_SETSTORE_KEYPAIRKS, alias);
			/*
			 * LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_CREATE_KEYSTORE),
			 * jksFilePath);
			 */
			throw new StorageException(ex);

		} finally {

			try {
				if (fos != null) {
					fos.flush();
					fos.close();
				}

			} catch (final Exception ex) {
				LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_OUTPUTSTREAM);
				throw new StorageException(ex);
			}
		}
	} // end of storeKeyPair

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.ericsson.nms.security.pki.store.CredentialWriter#addTrustedEntry(
	 * java.security.cert.Certificate, java.lang.String)
	 */
	@Override
	public void addTrustedEntry(final Certificate cert, final String alias)
			throws StorageException {

		// Store away the keystore.
		String myStoreFilePath = this.jksFilePath;
		FileOutputStream fos = null;

		try {
			// folder management
			if ((this.jksFolderPath != null)
					&& (!"".equalsIgnoreCase(this.jksFolderPath))) {
				// check if the directory exists
				final File file = new File(this.jksFolderPath);
				if (!file.exists()) {
					file.mkdir();
				}
				// build the new filename
				myStoreFilePath = this.jksFolderPath + File.separator + alias
						+ this.fileExtension();
			}

			System.out.println("addTrustedEntry " + alias + " in "
					+ myStoreFilePath);
			LOG.debug("addTrustedEntry " + alias + " in " + myStoreFilePath);

			// LOG.info(Logger
			// .getLogMessage(Logger.LOG_INFO_CREATE_START_TRUSTSTORE),
			// jksFilePath);
			final KeyStore ks = this.getKeyStore(myStoreFilePath);
			fos = new FileOutputStream(new File(myStoreFilePath));

			// store new data
			ks.setCertificateEntry(alias, cert);
			ks.store(fos, this.password.toCharArray());
			//
			// LOG.info(
			// Logger.getLogMessage(Logger.LOG_INFO_CREATE_END_TRUSTSTORE),
			// jksFilePath);
			// LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CREATE_TRUSTSTORE),
			// jksFilePath);

		} catch (final Exception ex) {
			LOG.error(ErrorMsg.API_ERROR_STORAGE_SETSTORE_CERTKS, alias);
			// LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_CREATE_TRUSTSTORE),
			// jksFilePath);
			throw new StorageException(ex);

		} finally {

			try {
				if (fos != null) {
					fos.flush();
					fos.close();
				}

			} catch (final Exception ex) {
				LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_OUTPUTSTREAM);
				throw new StorageException(ex);
			}
		}
	} // end of addTrustedEntry

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter
	 * #addCrlEntry(java.security.cert.CRL, java.lang.String)
	 */
	@Override
	public void addCrlEntry(final CRL crl, final String alias)
			throws StorageException {

		// TODO this format can not be used to save CRL

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter
	 * #deleteEntry(java.lang.String)
	 */
	@Override
	public void deleteEntry(final String alias) throws StorageException {

		// escape for no file
		final File file = new File(this.jksFilePath);
		if (!file.exists()) {
			return;
		}

		System.out.println("deleteEntry " + alias + " in " + this.jksFilePath);
		LOG.debug("deleteEntry " + alias + " in " + this.jksFilePath);

		// Store away the keystore.
		FileOutputStream fos = null;

		try {
			/*
			 * LOG.info(
			 * Logger.getLogMessage(Logger.LOG_INFO_CREATE_START_KEYSTORE),
			 * jksFilePath);
			 */
			final KeyStore ks = this.getKeyStore(this.jksFilePath);
			fos = new FileOutputStream(new File(this.jksFilePath));

			// Search for alias in the file
			final Enumeration<String> enumString = ks.aliases();
			while (enumString.hasMoreElements()) {
				final String element = enumString.nextElement();
				if (element.startsWith(alias.toLowerCase())) {
					// delete the entry
					ks.deleteEntry(element);
				}
			}

			ks.store(fos, this.password.toCharArray());

			// LOG.info(Logger.getLogMessage(Logger.LOG_INFO_CREATE_END_KEYSTORE),
			// jksFilePath);
			// LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CREATE_KEYSTORE),
			// jksFilePath);

		} catch (final Exception ex) {
			LOG.error(ErrorMsg.API_ERROR_STORAGE_DELETE_ENTRYKS, alias);
			/*
			 * LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_CREATE_KEYSTORE),
			 * jksFilePath);
			 */
			throw new StorageException(ex);

		} finally {
			try {
				if (fos != null) {
					fos.flush();
					fos.close();
				}
			} catch (final Exception ex) {
				LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_OUTPUTSTREAM);
				throw new StorageException(ex);
			}
		}
	} // end of deleteEntry

	/**
	 * getKeyStore
	 * 
	 * @return
	 * @throws StorageException
	 */
	private KeyStore getKeyStore(final String filename) throws StorageException {

		InputStream is = null;
		KeyStore ks = null;

		// load the keystore with the previous data (if any)
		final File file = new File(filename);
		try {
			ks = KeyStore.getInstance(this.storeType);
			if (!file.exists()) {
				ks.load(null, this.password.toCharArray());
			} else {
				// read the previous keystore
				is = new FileInputStream(file);
				ks.load(is, this.password.toCharArray());
			}
			return ks;
		} catch (final Exception e) {
			LOG.error(ErrorMsg.API_ERROR_STORAGE_LOAD_PREVKS, filename);
			throw new StorageException(e);
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (final Exception ex) {
					LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_INPUTSTREAM,
							filename);
					// No need to handle
					throw new StorageException(ex);
				}
			}
		}
	}

	/**
	 * fileExtension
	 * 
	 * @return String
	 */
	private String fileExtension() {

		if (StorageConstants.JCEKS_STORE_TYPE.equals(this.storeType)) {
			return ".jceks";
		}
		return ".jks";
	}

} // end of JKSWriter

