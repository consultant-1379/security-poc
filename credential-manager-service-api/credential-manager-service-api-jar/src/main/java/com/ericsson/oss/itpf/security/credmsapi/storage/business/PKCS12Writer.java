/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
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
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.io.Streams;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

public class PKCS12Writer implements CredentialWriter {

	/**
     * 
     */
	private static final Logger LOG = LogManager.getLogger(PKCS12Writer.class);

	{
		Security.addProvider(new BouncyCastleProvider());
	}

	public PKCS12Writer() {

	}

	/**
	 * PKCS 12 file path
	 */
	private String pkcs12FolderPath = "";
	private String pkcs12FilePath = "";

	/**
	 * String password
	 */
	private String password = "";

	/**
     * 
     */
	// private final String encryptionAlgorithm = "AES-256-CFB";

	/**
	 * @param pkcs12FilePath
	 * @param password
	 * @param overWriteFile
	 * @throws StorageException
	 */
	public PKCS12Writer(final String pkcs12FolderPath,
			final String pkcs12FilePath, final String password)
			throws StorageException {
		this();
		this.pkcs12FolderPath = pkcs12FolderPath;
		this.pkcs12FilePath = pkcs12FilePath;
		this.password = password;
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

		System.out.println("storeKeyPair " + alias + " in "
				+ this.pkcs12FilePath);
		LOG.debug("storeKeyPair " + alias + " in " + this.pkcs12FilePath);

		// load data
		final List<PKCS12SafeBag> storeBags = this
				.loadBags(this.pkcs12FilePath);

		try {
			//
			// build new bags
			//
			final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
			final Certificate cert = certificateChain[0];

			// private key bag (encrypted)
			final BcPKCS12PBEOutputEncryptorBuilder encBuilder = new BcPKCS12PBEOutputEncryptorBuilder(
					PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC,
					new CBCBlockCipher(new DESedeEngine()));
			final PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(
					(PrivateKey) key, encBuilder.build(this.password
							.toCharArray()));
			keyBagBuilder.addBagAttribute(
					PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
					new DERBMPString(alias /* + "_PRIVATE_KEY" */));
			keyBagBuilder.addBagAttribute(
					PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					extUtils.createSubjectKeyIdentifier(cert.getPublicKey()));

			// certificate bag
			final PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(
					(X509Certificate) cert);
			eeCertBagBuilder.addBagAttribute(
					PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
					new DERBMPString(alias + "_CERTIFICATE"));
			eeCertBagBuilder.addBagAttribute(
					PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					extUtils.createSubjectKeyIdentifier(cert.getPublicKey()));

			//
			// add new bags
			//
			storeBags.add(keyBagBuilder.build());
			storeBags.add(eeCertBagBuilder.build());

			// certificate path (from cert[1], the cert[0] has already been
			// added with link to private key
			for (int i = 1; i < certificateChain.length; i++) {
				final PKCS12SafeBagBuilder chainCertBagBuilder = new JcaPKCS12SafeBagBuilder(
						(X509Certificate) certificateChain[i]);
				chainCertBagBuilder.addBagAttribute(
						PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
						new DERBMPString(alias + "_CERTIFICATE[" + i + "]"));
				storeBags.add(chainCertBagBuilder.build());
			}

		} catch (final NoSuchAlgorithmException | IOException e) {
			throw new StorageException(e);
		}

		//
		// write
		//
		this.storeBags(this.pkcs12FilePath, this.password, storeBags);

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
		String myStoreFilePath = this.pkcs12FilePath;

		try {
			final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

			// folder management
			if ((this.pkcs12FolderPath != null)
					&& (!"".equalsIgnoreCase(this.pkcs12FolderPath))) {
				// check if the directory exists
				final File file = new File(this.pkcs12FolderPath);
				if (!file.exists()) {
					file.mkdir();
				}
				// build the new filename
				myStoreFilePath = this.pkcs12FolderPath + File.separator
						+ alias + this.fileExtension();
			}

			System.out.println("addTrustedEntry " + alias + " in "
					+ myStoreFilePath);
			LOG.debug("addTrustedEntry " + alias + " in " + myStoreFilePath);

			// load data
			final List<PKCS12SafeBag> storeBags = this
					.loadBags(myStoreFilePath);

			//
			// build new bags
			//

			// certificates bags
			final PKCS12SafeBagBuilder trustBagBuilder = new JcaPKCS12SafeBagBuilder(
					(X509Certificate) cert);
			trustBagBuilder.addBagAttribute(
					PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
					new DERBMPString(alias));
			trustBagBuilder.addBagAttribute(
					PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					extUtils.createSubjectKeyIdentifier(cert.getPublicKey()));

			//
			// add new bags
			//
			storeBags.add(trustBagBuilder.build());

			//
			// write
			//
			this.storeBags(myStoreFilePath, this.password, storeBags);

		} catch (final NoSuchAlgorithmException | IOException e) {
			throw new StorageException(e);
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
		final File file = new File(this.pkcs12FilePath);
		if (!file.exists()) {
			return;
		}

		System.out.println("deleteEntry " + alias + " in "
				+ this.pkcs12FilePath);
		LOG.debug("deleteEntry " + alias + " in " + this.pkcs12FilePath);

		// load data
		final List<PKCS12SafeBag> storeBags = this
				.loadBags(this.pkcs12FilePath);

		//
		// remove entries
		//
		final List<PKCS12SafeBag> cleanedBags = new ArrayList<PKCS12SafeBag>();
		final Iterator<PKCS12SafeBag> iterator = storeBags.iterator();
		while (iterator.hasNext()) {
			final PKCS12SafeBag checkingBag = iterator.next();
			final String friendlyName = this.readFriendlyName(checkingBag);

			if (!friendlyName.startsWith(alias)) {
				// save the entry
				cleanedBags.add(checkingBag);
			}
		}

		//
		// write
		//
		this.storeBags(this.pkcs12FilePath, this.password, cleanedBags);

	} // end of deleteEntry

	/**
	 * loadBags
	 * 
	 * @param filename
	 * @return
	 * @throws StorageException
	 */
	public List<PKCS12SafeBag> loadBags(final String filename)
			throws StorageException {

		FileInputStream fis = null;
		final List<PKCS12SafeBag> storeBags = new ArrayList<PKCS12SafeBag>();
		final InputDecryptorProvider inputDecryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
				.setProvider("BC").build(this.password.toCharArray());

		try {

			// load the keystore with the previous data (if any)
			final File file = new File(filename);

			if (!file.exists()) {
				return storeBags;
			}

			// read the previous keystore
			fis = new FileInputStream(file);
			final PKCS12PfxPdu pfx = new PKCS12PfxPdu(Streams.readAll(fis));
			fis.close();
			// extract all the bags
			final ContentInfo[] infos = pfx.getContentInfos();
			for (int i = 0; i != infos.length; i++) {
			    PKCS12SafeBagFactory dataFact;
				if (infos[i].getContentType().equals(
				        PKCSObjectIdentifiers.encryptedData)) {
				    dataFact = new PKCS12SafeBagFactory(
				            infos[i], inputDecryptorProvider);
				} else {
				    dataFact = new PKCS12SafeBagFactory(
				            infos[i]);
				}
				final PKCS12SafeBag[] bags = dataFact.getSafeBags();
				// store the bag
				for (int b = 0; b != bags.length; b++) {
				    storeBags.add(bags[b]);
				}
			}
		} catch (final Exception e) {
			throw new StorageException(e);
		} finally {
			try {
				if (fis != null) {
					fis.close();
				}
			} catch (final Exception ex) {
			}
		}
		return storeBags;

	} // end of loadBags

	/**
	 * storeBags
	 * 
	 * @param filename
	 * @param password
	 * @param storeBags
	 * @throws StorageException
	 */
	private void storeBags(final String filename, final String password,
			final List<PKCS12SafeBag> storeBags) throws StorageException {

		FileOutputStream fos = null;
		final PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();

		try {
			fos = new FileOutputStream(filename);

			// load all the bags
			final Iterator<PKCS12SafeBag> iterator = storeBags.iterator();
			while (iterator.hasNext()) {
				final PKCS12SafeBag bag = iterator.next();
				pfxPduBuilder.addData(bag);
			}

			// write a new file
			final PKCS12PfxPdu pfx = pfxPduBuilder.build(
					new BcPKCS12MacCalculatorBuilder(), password.toCharArray());
			// make sure we don't include indefinite length encoding
			fos.write(pfx.getEncoded(ASN1Encoding.DL));

		} catch (final Exception ex) {
			// LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_CREATE_KEYSTORE),
			// pkcs12FilePath);
			throw new StorageException(ex);

		} finally {
			try {
				if (fos != null) {
					fos.flush();
					fos.close();
				}
			} catch (final Exception ex) {
			}
		}
	} // end of storeBags

	/**
	 * readFriendlyName
	 * 
	 * @param bag
	 * @return
	 */
	String readFriendlyName(final PKCS12SafeBag bag) {

		String friendlyName = "";

		final Attribute[] attributes = bag.getAttributes();
		for (int a = 0; a != attributes.length; a++) {
			final Attribute attr = attributes[a];

			if (attr.getAttrType().equals(PKCS12SafeBag.friendlyNameAttribute)) {
				friendlyName = ((DERBMPString) attr.getAttributeValues()[0])
						.getString();
			}
		}
		return friendlyName;
	}

	/**
	 * fileExtension
	 * 
	 * @return String
	 */
	private String fileExtension() {

		return ".p12";
	}

} // end of PKCS12Writer

