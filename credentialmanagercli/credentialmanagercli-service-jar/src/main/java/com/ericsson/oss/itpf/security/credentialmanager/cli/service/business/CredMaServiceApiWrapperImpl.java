/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.business;

import java.util.*;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.*;
import com.ericsson.oss.itpf.security.credmsapi.api.InternalIfCredentialManagement;
import com.ericsson.oss.itpf.security.credmsapi.api.model.*;
import com.ericsson.oss.itpf.security.credmsapi.business.IfCertificateManagementImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerSubjectAltName.ALTERNATE_NAME_TYPE;

public class CredMaServiceApiWrapperImpl implements CredMaServiceApiWrapper {

        // TORF-562254 update log4j
	private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();

	InternalIfCredentialManagement credMaServiceApi = new IfCertificateManagementImpl();


	/**
	 * 
	 */
	public CredMaServiceApiWrapperImpl() {
		// empty constructor to allow to instantiate it
	}

	/**
	 * @return the credMaServiceApi
	 */
	public InternalIfCredentialManagement getCredMaServiceApi() {
		return this.credMaServiceApi;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.
	 * CredMaServiceApiWrapper#manageCertificateAndTrust(java.lang.String,
	 * java.lang.String, java.lang.String, java.util.List, java.util.List,
	 * com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.
	 * CredMaCliCertificateExtension)
	 */
	@Override
	public Boolean manageCertificateAndTrust(final String entityName,
			final String distinguishName,
			final CredentialManagerSubjectAltName subjectAltName,
			final String entityProfileName,
			final List<CredentialManagerKeyStore> keystoreInfoList,
			final List<CredentialManagerTrustStore> truststoreInfoList,
			final List<CredentialManagerTrustStore> crlstoreInfoList,
			final CredentialManagerCertificateExt certificateExt,
			final boolean certficateChain, final boolean forceOverwrite)
			throws CredentialManagerException {

		// data structure transformation
		final SubjectAlternativeNameType altName = this
				.buildSubjectAltName(subjectAltName);
		final List<KeystoreInfo> ksInfoList = this
				.buildKeystoreInfoList(keystoreInfoList);
		final List<TrustStoreInfo> tsInfoList = this
				.buildTruststoreInfoList(truststoreInfoList);
		final List<TrustStoreInfo> crlInfoList = this
				.buildTruststoreInfoList(crlstoreInfoList);
		CredentialManagerCertificateExtension certificateExtension = null;

		// in case of overwrite, the old keystores are deleted
		if (forceOverwrite) {
			this.deleteOldStoreFiles(ksInfoList, tsInfoList);
		}

		// copy CredentialManagerCertificateExtension
		certificateExtension = new CredentialManagerCertificateExtensionImpl(
				certificateExt.getAttributes(), certificateExt
						.getSubjectAlternativeName()
						.getSubjectAlternativeName());

		// call the CredentialManager Service API to communicate with the
		// Credential Manager Service

		// credMaServiceApi = new IfCertificateManagementImpl();

		LOG.info(Logger.getLogMessage(Logger.LOG_INFO_ISSUECERTIFICATE),
				"Call Service API manageCertificateAndTrust");

		Boolean result = false;
		try {
			result = this.credMaServiceApi.issueCertificate(entityName,
					distinguishName, altName, entityProfileName, ksInfoList,
					tsInfoList, crlInfoList, certificateExtension,
					certficateChain);
		} catch (final Exception e) {
			e.printStackTrace();
			throw new CredentialManagerException();
		}

		return result;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.
	 * CredMaServiceApiWrapper#manageMyOwnCertificate(java.lang.String,
	 * com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.
	 * CredentialManagerSubjectAltName, java.lang.String, java.util.List,
	 * com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.
	 * CredentialManagerCertificateExt)
	 */
	@Override
	public Boolean manageCredMaCertificate(final String entityName,
			final String distinguishName,
			final CredentialManagerSubjectAltName subjectAltName,
			final String entityProfileName,
			final List<CredentialManagerKeyStore> keystoreInfoList,
			final List<CredentialManagerTrustStore> truststoreInfoList,
			final List<CredentialManagerTrustStore> crlstoreInfoList,
			final CredentialManagerCertificateExt certificateExt,
			final boolean forceOverwrite, final boolean noLoop, final boolean isCheck,
			final boolean firstDayRun)
			throws CredentialManagerException {

		// data structure transformation
		final SubjectAlternativeNameType altName = this
				.buildSubjectAltName(subjectAltName);
		final List<KeystoreInfo> ksInfoList = this
				.buildKeystoreInfoList(keystoreInfoList);
		final List<TrustStoreInfo> tsInfoList = this
				.buildTruststoreInfoList(truststoreInfoList);
		final List<TrustStoreInfo> crlInfoList = this
				.buildTruststoreInfoList(crlstoreInfoList);
		CredentialManagerCertificateExtension certificateExtension = null;

		// in case of overwrite, the old keystores are deleted
		if (forceOverwrite) {
			this.deleteOldStoreFiles(ksInfoList, tsInfoList);
		}

		// copy CredentialManagerCertificateExtension
		certificateExtension = new CredentialManagerCertificateExtensionImpl(
				certificateExt.getAttributes(), certificateExt
						.getSubjectAlternativeName()
						.getSubjectAlternativeName());

		// call the CredentialManager Service API to communicate with the
		// Credential Manager Service

		// credMaServiceApi = new IfCertificateManagementImpl();

		LOG.info(Logger.getLogMessage(Logger.LOG_INFO_CLICERTIFICATE),
				"Call Service API manageCertificateAndTrust");

		Boolean result = false;
		try {
			LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CLICERTIFICATE),
					".....call REST");
			result = this.credMaServiceApi.issueCertificateRESTchannel(
					entityName, distinguishName, altName, entityProfileName,
					ksInfoList, tsInfoList, crlInfoList, certificateExtension,
					noLoop, isCheck, firstDayRun);

		} catch (final Exception e) {
			throw new CredentialManagerException();
		}

		return result;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.
	 * CredMaServiceApiWrapper#manageCheck(java.lang.String, java.lang.String,
	 * com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.
	 * CredentialManagerSubjectAltName, java.lang.String, java.util.List,
	 * java.util.List, java.util.List,
	 * com.ericsson.oss.itpf.security.credentialmanager
	 * .cli.service.api.CredentialManagerCertificateExt, boolean)
	 */
	@Override
	public CheckResult manageCheck(final String entityName,
			final String distinguishName,
			final CredentialManagerSubjectAltName subjectAltName,
			final String entityProfileName,
			final List<CredentialManagerKeyStore> keystoreInfoList,
			final List<CredentialManagerTrustStore> truststoreInfoList,
			final List<CredentialManagerTrustStore> crlstoreInfoList,
			final CredentialManagerCertificateExt certificateExt,
			final boolean certificateChain,
			final boolean firstDailyRun) throws CredentialManagerException {
	  
	    
		// data structure transformation
        SubjectAlternativeNameType altName;
        List<KeystoreInfo> ksInfoList;
        List<TrustStoreInfo> tsInfoList;
        List<TrustStoreInfo> crlInfoList;
        CredentialManagerCertificateExtension certificateExtension;
        try {
            altName = this
            		.buildSubjectAltName(subjectAltName);
            ksInfoList = this
            		.buildKeystoreInfoList(keystoreInfoList);
            tsInfoList = this
            		.buildTruststoreInfoList(truststoreInfoList);
            crlInfoList = this
            		.buildTruststoreInfoList(crlstoreInfoList);
            certificateExtension = null;

            // in case of overwrite, the old keystores are deleted
            // if (forceOverwrite) {
            // this.deleteOldStoreFiles(ksInfoList, tsInfoList);
            // }

            // copy CredentialManagerCertificateExtension
            certificateExtension = new CredentialManagerCertificateExtensionImpl(
            		certificateExt.getAttributes(), certificateExt
            				.getSubjectAlternativeName()
            				.getSubjectAlternativeName());
        } catch (final Exception e1) {//NOSONAR
            LOG.error("manageCheck - data trasformation : " + e1.getMessage());
            throw new CredentialManagerException();
        }

		// call the CredentialManager Service API to communicate with the
		// Credential Manager Service

	//	this.credMaServiceApi = new IfCertificateManagementImpl();

		//
		// CheckResult Obj
		// to return
		//

		final CheckResult result = new CheckResult();

		//
		// Check Certificate Validity
		//
		final Properties props = PropertiesReader.getConfigProperties();
		final String valueProp = props.getProperty("servicemanager.implementation",
				"MOCKED_API");
		LOG.info(Logger.getLogMessage(Logger.LOG_INFO_ISSUECERTIFICATE),
				"Call Service API checkCertificateAction for entity "
						+ entityName);

		Boolean result_certificate = false;
		try {
			if (valueProp.equals("MOCKED_API")) {
				result_certificate = true;
			} else {
				System.out.println("Call Service API checkCertificateAction for entity "
								+ entityName);
				result_certificate = this.credMaServiceApi.checkAndUpdateCertificate(
						entityName, distinguishName, altName,
						entityProfileName, ksInfoList, certificateExtension,
						certificateChain, firstDailyRun);
				System.out.println("check result is  "+result_certificate);
			}
		} catch (final Exception e) {//NOSONAR
		    LOG.error("Executing checkAndUpdateCertificate "+entityName+" [Failed]:"+e.getMessage());
		    throw new CredentialManagerException();
		}

		//
		// Check Trust Validity
		//
		LOG.info(Logger.getLogMessage(Logger.LOG_INFO_ISSUECERTIFICATE),
				"Call Service API checkTrust for entity " + entityName);

		Boolean result_trust = false;
		try {
			if (valueProp.equals("MOCKED_API")) {
			    System.out.println("..... Service API checkTrust (MOCKED) ");
			} else {
				System.out.println("Call Service API checkTrustAction for entity "+ entityName);
				result_trust = this.credMaServiceApi.checkAndUpdateTrusts(
						entityName, entityProfileName,  tsInfoList, 
						 false);
				System.out.println("check result is  "+result_trust);
			}
		} catch (final Exception e) {//NOSONAR
		    LOG.error("Executing checkAndUpdateTrusts "+entityName+" [Failed]:"+e.getMessage());
		    throw new CredentialManagerException();
		}

		//
		// Check CRL Validity
		//
		LOG.info(Logger.getLogMessage(Logger.LOG_INFO_ISSUECERTIFICATE),
				"Call Service API checkCRLAction for entity " + entityName);
		
		Boolean result_crl = false;
		try {
			if (valueProp.equals("MOCKED_API")) {
			    System.out.println("..... Service API checkCRL (MOCKED) ");
			} else {
			    System.out.println("Call Service API checkCRL for entity "+ entityName);
			    result_crl = this.credMaServiceApi.checkAndUpdateCRL(entityName, crlInfoList, result_trust);
			    System.out.println("check result is  "+result_crl);
			}
		} catch (final Exception e) {//NOSONAR
		    LOG.error("Executing checkAndUpdateCRL "+entityName+" [Failed]:"+e.getMessage());
		    throw new CredentialManagerException();
		}

		result.setResult("certificateUpdate", result_certificate);
		result.setResult("trustUpdate", result_trust);
		result.setResult("crlUpdate", result_crl);

		return result;
	}

    @Override
    public CheckResult manageCheckTrustAndCRL(final String trustProfileName, 
            final List<CredentialManagerTrustStore> truststoreInfoList, final List<CredentialManagerTrustStore> crlstoreInfoList)
            throws CredentialManagerException {
        
        final CheckResult result = new CheckResult();
        final Properties props = PropertiesReader.getConfigProperties();
        final String valueProp = props.getProperty("servicemanager.implementation", "MOCKED_API");

        // data structure transformation
        final List<TrustStoreInfo> tsInfoList = this.buildTruststoreInfoList(truststoreInfoList);
        final List<TrustStoreInfo> crlInfoList = this.buildTruststoreInfoList(crlstoreInfoList);

        //
        // Check Trust Validity
        //
        Boolean result_trust = false;
        try {
            if (valueProp.equals("MOCKED_API")) {
                System.out.println("..... Service API checkTrust (MOCKED) ");
                //result_trust = false;
            } else {
                System.out.println("Call Service API checkTrustAction for trustProfile " + trustProfileName);
                result_trust = this.credMaServiceApi.checkAndUpdateTrustsTP(trustProfileName, tsInfoList);
                System.out.println("check result is  "+result_trust);
            }
        } catch (final Exception e) {//NOSONAR
            LOG.error("Executing checkAndUpdateTrustsTP "+trustProfileName+" [Failed]:"+e.getMessage());
            throw new CredentialManagerException();
        }

        //
        // Check CRL Validity
        //
        Boolean result_crl = false;
        try {
            if (valueProp.equals("MOCKED_API")) {
                System.out.println("..... Service API checkCRL (MOCKED) ");
                //result_crl = false;
            } else {
                System.out.println("Call Service API checkCRL for trustprofile " + trustProfileName);
                result_crl = this.credMaServiceApi.checkAndUpdateCRL_TP(trustProfileName, crlInfoList, result_trust);
                System.out.println("check result is  " + result_crl);

            }
        } catch (final Exception e) {//NOSONAR
            LOG.error("Executing checkAndUpdateCRL_TP "+trustProfileName+" [Failed]:"+e.getMessage());
            throw new CredentialManagerException();
        }
        
        result.setResult("certificateUpdate", Boolean.FALSE);
        result.setResult("trustUpdate", result_trust);
        result.setResult("crlUpdate", result_crl);

        return result;
    }



	//
	// --------------------------------------------- utility
	//

	/**
	 * @param truststireInfoList
	 * @param tsInfoList
	 */
	private List<TrustStoreInfo> buildTruststoreInfoList(
			final List<CredentialManagerTrustStore> truststoreInfoList) {

                if(truststoreInfoList == null) {
                    LOG.error("The truststore/crlstore information list cannot be null");
                    throw new CredentialManagerException("truststoreInfoList cannot be null");
                }
		final List<TrustStoreInfo> tsInfoList = new ArrayList<TrustStoreInfo>();
		// copy truststore info
		final Iterator<CredentialManagerTrustStore> truststoreIter = truststoreInfoList
				.iterator();
		while (truststoreIter.hasNext()) {
			final CredentialManagerTrustStore truststoreItem = truststoreIter
					.next();
			final TrustStoreInfo newKeystore = new TrustStoreInfo(
					truststoreItem.getLocation(), truststoreItem.getFolder(),
					this.convertTrustFormat(truststoreItem.getType()),
					truststoreItem.getPassword(), truststoreItem.getAlias(),
					this.convertTrustSource(truststoreItem.getSource()));
			tsInfoList.add(newKeystore);
		}
		return tsInfoList;
	}

	/**
	 * @param keystoreInfoList
	 * @param ksInfoList
	 */
	private List<KeystoreInfo> buildKeystoreInfoList(
			final List<CredentialManagerKeyStore> keystoreInfoList) {

	        if(keystoreInfoList == null) {
	            LOG.error("The keystore information list cannot be null");
	            throw new CredentialManagerException("keystoreInfoList cannot be null");
	        }
		final List<KeystoreInfo> ksInfoList = new ArrayList<KeystoreInfo>();
		// copy keystore info
		final Iterator<CredentialManagerKeyStore> keystoreIter = keystoreInfoList
				.iterator();
		while (keystoreIter.hasNext()) {
			final CredentialManagerKeyStore keystoreItem = keystoreIter.next();
			final KeystoreInfo newKeystore = this
					.buildKeystoreInfo(keystoreItem);
			ksInfoList.add(newKeystore);
		}
		return ksInfoList;
	}

	/**
	 * @param keystoreItem
	 * @return
	 */
	private KeystoreInfo buildKeystoreInfo(
			final CredentialManagerKeyStore keystoreItem) {
	    
	        if(keystoreItem == null) {
	            LOG.error("A keystore information item cannot be null");
	            throw new CredentialManagerException("keystoreItem cannot be null");
	        }
	    
		final KeystoreInfo newKeystore = new KeystoreInfo(
				keystoreItem.getKeyStorelocation(),
				keystoreItem.getPrivateKeyLocation(),
				keystoreItem.getCertificateLocation(), "",
				this.convertKeyFormat(keystoreItem.getType()),
				keystoreItem.getPassword(), keystoreItem.getAlias());
		return newKeystore;
	}

	/**
	 * @param ksInfoList
	 * @param tsInfoList
	 */
	private void deleteOldStoreFiles(final List<KeystoreInfo> ksInfoList,
			final List<TrustStoreInfo> tsInfoList) {
	    
	        if(ksInfoList == null) {
                    LOG.error("The keystore information list cannot be null");
	            throw new CredentialManagerException("ksInfoList cannot be null");
	        }
	        else if(tsInfoList == null) {
	            LOG.error("The truststore information list cannot be null");
	            throw new CredentialManagerException("tsInfoList cannot be null");
	        }
		// we use the "service api" structures becuase they have better methods
		// to delete items
		final Iterator<KeystoreInfo> ksInfoIter = ksInfoList.iterator();
		while (ksInfoIter.hasNext()) {
			final KeystoreInfo keystoreItem = ksInfoIter.next();
			keystoreItem.delete();
		}
		final Iterator<TrustStoreInfo> tsInfoIter = tsInfoList.iterator();
		while (tsInfoIter.hasNext()) {
			final TrustStoreInfo keystoreItem = tsInfoIter.next();
			keystoreItem.delete();
		}
	}

	/**
	 * @param subjectAltName
	 * @return
	 */
	@SuppressWarnings("incomplete-switch") //just ignore cases not explicitly defined
    private SubjectAlternativeNameType buildSubjectAltName(
			final CredentialManagerSubjectAltName subjectAltName) {
	    
	        if(subjectAltName == null) {
	            LOG.error("The subjectAltName cannot be null");
	            throw new CredentialManagerException("subjectAltName cannot be null");
	        }
		SubjectAlternativeNameType altName;
		// build SubjectAlternativeNameType
		altName = new SubjectAlternativeNameType();
		for(int i=0; i<subjectAltName.getType().size(); i++) {
		    ALTERNATE_NAME_TYPE type = subjectAltName.getType().get(i);
		    switch (type) {
		    case DIRECTORY_NAME:
		        altName.setDirectoryname(subjectAltName.getValue().get(i));
		        break;
		    case DNS:
		        altName.setDns(subjectAltName.getValue().get(i));
		        break;
		    case EMAIL:
		        altName.setEmail(subjectAltName.getValue().get(i));
		        break;
		    case URI:
		        altName.setUri(subjectAltName.getValue().get(i));
		        break;
		    case IP_ADDRESS:
		        altName.setIpaddress(subjectAltName.getValue().get(i));
		        break;
		    case OTHER_NAME:
		        altName.setOthername(subjectAltName.getValue().get(i));
		        break;
		    case REGISTERED_ID:
		        altName.setRegisteredid(subjectAltName.getValue().get(i));
		        break;
		    }
		}
		return altName;
	}


	/**
	 * CertificateFormat convert from string to enum
	 * 
	 * @param type
	 * @returnboolean
	 */
	private CertificateFormat convertKeyFormat(final String type) {
		switch (type) {
		case StoreConstants.BASE64_STORE_TYPE:
			return CertificateFormat.BASE_64;
			// break;
		case StoreConstants.JCEKS_STORE_TYPE:
			return CertificateFormat.JCEKS;
			// break;
		case StoreConstants.JKS_STORE_TYPE:
			return CertificateFormat.JKS;
			// break;
		case StoreConstants.PKCS12_STORE_TYPE:
			return CertificateFormat.PKCS12;
			// break;
		}
		return null;
	}

	/**
	 * CertificateFormat convert from string to enum
	 * 
	 * @param type
	 * @return
	 */
	private TrustFormat convertTrustFormat(final String type) {
		switch (type) {
		case StoreConstants.BASE64_STORE_TYPE:
			return TrustFormat.BASE_64;
			// break;
		case StoreConstants.JCEKS_STORE_TYPE:
			return TrustFormat.JCEKS;
			// break;
		case StoreConstants.JKS_STORE_TYPE:
			return TrustFormat.JKS;
			// break;
		case StoreConstants.PKCS12_STORE_TYPE:
			return TrustFormat.PKCS12;
			// break;
		}
		return null;
	}

	/**
	 * convertTrustSource 
	 * 
	 * @param source
	 * @return
	 */
	private TrustSource convertTrustSource(final String source) {

		switch (source) {
		case SourceConstants.TRUST_SOURCE_INTERNAL:
			return TrustSource.INTERNAL;
		case SourceConstants.TRUST_SOURCE_EXTERNAL:
			return TrustSource.EXTERNAL;
		case SourceConstants.TRUST_SOURCE_BOTH:
			return TrustSource.BOTH;
		}
		return null;
	} 
        
}
