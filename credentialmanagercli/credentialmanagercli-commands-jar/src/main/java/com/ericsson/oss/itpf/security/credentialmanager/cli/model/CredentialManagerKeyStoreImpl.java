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
package com.ericsson.oss.itpf.security.credentialmanager.cli.model;

import java.io.File;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.KeyStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerKeyStore;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.StoreConstants;

/**
 * 
 * Hold the KeyStore that comes from XMLBeans generated based on the XSD for
 * credential manager
 * 
 */
public class CredentialManagerKeyStoreImpl implements CredentialManagerKeyStore {
	/**
     * 
     */
	private static final long serialVersionUID = 8547613804436273509L;
	private String privateKeyLocation = "";
	private String certificateLocation = "";
	private String keyStorelocation = "";
//	private String keyStorefolder = "";
	private String alias = "";
	private String password = "";
	private String type;

	public CredentialManagerKeyStoreImpl(final Object keyStoreObj) {

		KeyStoreType keyStore;

		if (keyStoreObj != null && keyStoreObj instanceof KeyStoreType) {
			keyStore = (KeyStoreType) keyStoreObj;
		} else {
			throw new CredentialManagerException(
					"Loading information key store: it is not a KeyStoreType instance[Failed]");
		}

		this.setJKSFormat(keyStore);
		this.setJCEKSFormat(keyStore);
		this.setPKCS12Format(keyStore);
		this.setBASE64Format(keyStore);
		
	        // check length of password
                if (!this.isValidPassword()) {
                    throw new CredentialManagerException(
                            "key store password must be at least 6 characters long [Failed]");
                }
                

	}

	/**
	 * @param keyStore
	 */
	private void setBASE64Format(final KeyStoreType keyStore) {
		if (keyStore.getBase64Keystore() != null) {

			if (keyStore.getBase64Keystore().getStorealias() != null) {
				this.setAlias(keyStore.getBase64Keystore().getStorealias());
			}

			if (keyStore.getBase64Keystore().getStorelocation() != null) {
				this.setKeyStorelocation(keyStore.getBase64Keystore()
						.getStorelocation());
			}

			//if (keyStore.getBase64Keystore().getStorefolder() != null) {
			//	this.setKeyStorefolder(keyStore.getBase64Keystore()
			//			.getStorefolder());
			//}

			if (keyStore.getBase64Keystore().getKeyfilelocation() != null) {
				this.setPrivateKeyLocation(keyStore.getBase64Keystore()
						.getKeyfilelocation().trim());
			}

			if (keyStore.getBase64Keystore().getCertificatefilelocation() != null) {
				this.setCertificateLocation(keyStore.getBase64Keystore()
						.getCertificatefilelocation().trim());
			}

			if (keyStore.getBase64Keystore().getStorepassword() != null) {
				this.setPassword(keyStore.getBase64Keystore()
						.getStorepassword().trim());
			}

			this.setType(StoreConstants.BASE64_STORE_TYPE);
		}
	}

	/**
	 * @param keyStore
	 */
	private void setPKCS12Format(final KeyStoreType keyStore) {
		if (!(keyStore.getPkcs12Keystore() == null)) {

			if (keyStore.getPkcs12Keystore().getStorealias() != null) {
				this.setAlias(keyStore.getPkcs12Keystore().getStorealias()
						.trim());
			}

			if (keyStore.getPkcs12Keystore().getStorelocation() != null) {
				this.setKeyStorelocation(keyStore.getPkcs12Keystore()
						.getStorelocation().trim());
			}

			//if (keyStore.getPkcs12Keystore().getStorefolder() != null) {
			//	this.setKeyStorefolder(keyStore.getPkcs12Keystore()
			//			.getStorefolder().trim());
			//}

			if (keyStore.getPkcs12Keystore().getStorepassword() != null) {
				this.setPassword(keyStore.getPkcs12Keystore().getStorepassword()
						.trim());
			}

			this.setType(StoreConstants.PKCS12_STORE_TYPE);
		}
	}

	/**
	 * @param keyStore
	 */
	private void setJKSFormat(final KeyStoreType keyStore) {
		if (keyStore.getJkskeystore() != null) {

			if (keyStore.getJkskeystore().getStorealias() != null) {
				this.setAlias(keyStore.getJkskeystore().getStorealias().trim());
			}

			if (keyStore.getJkskeystore().getStorelocation() != null) {
				this.setKeyStorelocation(keyStore.getJkskeystore()
						.getStorelocation().trim());
			}

			//if (keyStore.getJkskeystore().getStorefolder() != null) {
			//	this.setKeyStorefolder(keyStore.getJkskeystore()
			//			.getStorefolder().trim());
			//}

			if (keyStore.getJkskeystore().getStorepassword() != null) {
				this.setPassword(keyStore.getJkskeystore().getStorepassword().trim());
			}
			this.setType(StoreConstants.JKS_STORE_TYPE);
		}
	}

	/**
	 * @param keyStore
	 */
	private void setJCEKSFormat(final KeyStoreType keyStore) {
		if (keyStore.getJcekskeystore() != null) {

			if (keyStore.getJcekskeystore().getStorealias() != null) {
				this.setAlias(keyStore.getJcekskeystore().getStorealias()
						.trim());
			}

			if (keyStore.getJcekskeystore().getStorelocation() != null) {
				this.setKeyStorelocation(keyStore.getJcekskeystore()
						.getStorelocation().trim());
			}

			//if (keyStore.getJcekskeystore().getStorefolder() != null) {
			//	this.setKeyStorefolder(keyStore.getJcekskeystore()
			//			.getStorefolder().trim());
			//}

			if (keyStore.getJcekskeystore().getStorepassword() != null) {
				this.setPassword(keyStore.getJcekskeystore().getStorepassword()
						.trim());
			}
			this.setType(StoreConstants.JCEKS_STORE_TYPE);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerKeyStore #getPrivateKeyLocation()
	 */
	@Override
	public String getPrivateKeyLocation() {
		return this.privateKeyLocation;
	}

	/**
	 * @param privateKeyLocation
	 *            the privateKeyLocation to set
	 */
	private void setPrivateKeyLocation(final String privateKeyLocation) {
		this.privateKeyLocation = privateKeyLocation;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerKeyStore #getCerticateLocation()
	 */
	@Override
	public String getCertificateLocation() {
		return this.certificateLocation;
	}

	/**
	 * @param certicateLocation
	 *            the certicateLocation to set
	 */
	private void setCertificateLocation(final String certicateLocation) {
		this.certificateLocation = certicateLocation;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerKeyStore #getKeyStorelocation()
	 */
	@Override
	public String getKeyStorelocation() {
		return this.keyStorelocation;
	}

//	/*
//	 * (non-Javadoc)
//	 * 
//	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
//	 * CredentialManagerKeyStore #getKeyStorefolder()
//	 */
//	@Override
//	public String getKeyStorefolder() {
//		return this.keyStorefolder;
//	}

	/**
	 * @param keyStorelocation
	 *            the keyStorelocation to set
	 */
	private void setKeyStorelocation(final String keyStorelocation) {
		this.keyStorelocation = keyStorelocation;
	}

//	/**
//	 * @param keyStorelocation
//	 *            the keyStorefolder to set
//	 */
//	private void setKeyStorefolder(final String keyStorefolder) {
//		this.keyStorefolder = keyStorefolder;
//	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerKeyStore #getAlias()
	 */
	@Override
	public String getAlias() {
		return this.alias;
	}

	/**
	 * @param alias
	 *            the alias to set
	 */
	private void setAlias(final String alias) {
		this.alias = alias;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerKeyStore #getPassword()
	 */
	@Override
	public String getPassword() {
		return this.password;
	}

	/**
	 * @param password
	 *            the password to set
	 */
	private void setPassword(final String password) {
		this.password = password;
	}

	/**
         * 
         * @return
         */
        private boolean isValidPassword() {
            if (this.password != null && !"".equals(this.password)) {
                return (this.password.length() > 5);
            }
            return true;
        }
        
        
	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerKeyStore #getType()
	 */
	@Override
	public String getType() {
		return this.type;
	}

	/**
	 * @param type
	 *            the type to set
	 */
	private void setType(final String type) {
		this.type = type;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.
	 * CredentialManagerKeyStore#exists()
	 */
	@Override
	public boolean exists() {
		
//		// check folder
//		final File keyStorefolderFile = new File(this.keyStorefolder);
//		if (keyStorefolderFile.exists() && keyStorefolderFile.isDirectory()) {
//			final File[] listOfFiles = keyStorefolderFile.listFiles();
//			for (int i = 0; i < listOfFiles.length; i++) {
//			      if (listOfFiles[i].isFile()) {
//			    	  if (listOfFiles[i].getName().contains(this.alias)) {
//			    		  return true;
//			    	  }
//			      }
//			}
//		}

		//check files
		return ((new File(this.privateKeyLocation).exists()) ||
				(new File(this.certificateLocation).exists()) || 
				(new File(this.keyStorelocation).exists()) );
	}
	
	@Override
	public void delete() {
		
//		// delete file inside folder
//		final File keyStorefolderFile = new File(this.keyStorefolder);
//		if (keyStorefolderFile.exists() && keyStorefolderFile.isDirectory()) {
//			final File[] listOfFiles = keyStorefolderFile.listFiles();
//			for (int i = 0; i < listOfFiles.length; i++) {
//			      if (listOfFiles[i].isFile()) {
//			    	  if (listOfFiles[i].getName().contains(this.alias)) {
//			    		  listOfFiles[i].delete();
//			    	  }
//			      }
//			}
//		}
		// delete store files
		final File privateKeyLocationFile = new File(this.privateKeyLocation);
		if (privateKeyLocationFile.exists()) {
			privateKeyLocationFile.delete();
		}
		final File certificateLocationFile = new File(this.certificateLocation);
		if (certificateLocationFile.exists()) {
			certificateLocationFile.delete();
		}	
		final File keyStorelocationFile = new File(this.keyStorelocation);
		if (keyStorelocationFile.exists()) {
			keyStorelocationFile.delete();
		}		
	}
	
}  // end of CredentialManagerKeyStoreImpl
