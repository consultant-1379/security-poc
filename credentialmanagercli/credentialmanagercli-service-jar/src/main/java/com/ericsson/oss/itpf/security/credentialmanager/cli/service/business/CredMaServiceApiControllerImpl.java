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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.business;

import java.io.File;
import java.util.*;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.*;

public class CredMaServiceApiControllerImpl implements
		CredMaServiceApiController {

        // TORF-562254 update log4j
	private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();

	private final Properties configProperties = PropertiesReader
			.getConfigProperties();
	final CredMaServiceApiWrapper serviceApi = new CredMaServiceApiWrapperFactory()
			.getInstance(this.configProperties
					.getProperty("servicemanager.implementation"));

	@Override
	public int generateKeyAndTrustStore(
			final ApplicationCertificateConfigInformation appInfo,
			final boolean forceOverWriteIn) {

		final ApplicationCertificateConfigInformation appClientConfig = appInfo;
		final boolean forceOverWrite = forceOverWriteIn;
		int resultCode = 0;

		try {
			for (final CredentialManagerApplication credMApplicationInfo : appClientConfig
					.getApplicationsInfo()) {

				for (final CredentialManagerCertificate credMCertificateInfo : credMApplicationInfo
						.getCertificates()) {

					// check if keystore or truststore already exist
					/**
					 * TOBE F.M. 28/04/2015 This check have to be reworked cause
					 * new approach for the truststore (everytime overWrited)
					 **/
					// if (this.verifyKSExists(forceOverWrite,
					// credMCertificateInfo) ||
					// this.verifyTSExists(forceOverWrite,
					// credMCertificateInfo)) {
					// throw new
					// CredentialManagerException(Logger.getLogMessage(Logger.LOG_ERROR_CREATE_KSTS));
					// }

					// prepare the parameters
					final CredentialManagerTBSCertificate tbsCertificate = credMCertificateInfo
							.getTbsCertificate();
					final CredentialManagerCertificateExt certificateExtensionInfo = tbsCertificate
							.getCertificateExtension();

					// call the remote service (via local API)
					Boolean result = false;
					try {
						result = this.serviceApi.manageCertificateAndTrust(
								tbsCertificate.getEntityName(), // entityName,
								tbsCertificate.getSubjectDN(), // distinguishName
								certificateExtensionInfo
										.getSubjectAlternativeName(), // subjectAltName,
								credMCertificateInfo.getEndEntityProfileName(), // entityProfileName,
								credMCertificateInfo.getKeyStores(), // keystoreInfoList,
								credMCertificateInfo.getTrustStores(), // truststoreInfoList,
								credMCertificateInfo.getCrlStores(), // crlstoreInfoList,
								certificateExtensionInfo, // certificateExtension
								credMCertificateInfo.getCertificateChain(), // certficateChain
								forceOverWrite);
						if (credMCertificateInfo.getPostScript()
								.getPostScriptCmd() != null) {

							this.executePostScript(credMCertificateInfo.getPostScript());
						}
						//
						// Insert in a List Operations to do
						//

						if (!result) {
							resultCode = -1;
						}
					} catch (final Exception e) {//NOSONAR
					    LOG.error("Executing manageCertificateAndTrust [Failed]:"+e.getMessage());
					    resultCode = -9;
					}
				} // end of for Certificates
				
				// TrustOnly management

				if (!credMApplicationInfo.getTrustStoresOnly().isEmpty()) {
				    System.out.println("------------TRUST ONLY in generateKeyAndTrustStore ---------");
	                            for (final CredentialManagerTrustStoreOnly trustStoreOnly : credMApplicationInfo
	                                .getTrustStoresOnly() ) {
	                        
	                                System.out.println("------------"+trustStoreOnly.getTrustProfileName());
	                                
	                                // prepare data
	                                final String trustProfileName = trustStoreOnly.getTrustProfileName();
	                                
	                                
	                                // call the remote service (via local API)
	                                CheckResult result = new CheckResult();
                                        try {
                                                result = this.serviceApi.manageCheckTrustAndCRL(trustProfileName, 
                                                        trustStoreOnly.getTrustStores(), trustStoreOnly.getCrlStores());

                                                if (trustStoreOnly.getPostScript()
                                                        .getPostScriptCmd() != null) {

                                                    this.executePostScript(trustStoreOnly.getPostScript());
                                                }

                                                if (!result.isAllFalse()) {
                                                    resultCode = -1;
                                        }
                                        } catch (final Exception e) { //NOSONAR
                                            LOG.error("Executing manageCheckTrustAndCRL [Failed]:"+e.getMessage());
                                            resultCode = -9;
                                        }                                                        
	                            } // end for getTrustStoresOnly
				}// enf if getTrustStoresOnly
				
			} // end of for Applications

		} catch (final Exception e) {
			throw new CredentialManagerException(e);
		}

		return resultCode;
	}

	/**
	 * @param credMCertificateInfo
	 */

	public void executePostScript(final CredentialManagerPostScriptCaller postScriptInfo) {
	   
	    final CredentialManagerCommandType postScriptCmd = postScriptInfo.getPostScriptCmd();
	    
		final List<String> shCmd = new ArrayList<String>();

		final String pathCommand = postScriptCmd.getPathname().get(0);
		LOG.info("Executing XML PostScript command " + pathCommand + " [Failed]");
		shCmd.add(pathCommand);
		if (postScriptCmd.getParameterValue() != null) {
			final Iterator<String> i = postScriptCmd.getParameterValue().iterator();
			while (i.hasNext()) {
				shCmd.add(i.next());
			}
		}
		final File file = new File(pathCommand);
		file.setExecutable(true);
		try {
			final ProcessBuilder pb = new ProcessBuilder(shCmd);
			final Process p = pb.start();
			p.waitFor();
		} catch (final Exception e) {
	                LOG.error("Executing XML PostScript command " + pathCommand + " [Failed]");
			e.printStackTrace();
		}
		file.setExecutable(false);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.
	 * CredMaServiceApiController
	 * #generateMyOwnCertificate(com.ericsson.oss.itpf.
	 * security.credentialmanager.cli.service.api.
	 * ApplicationCertificateConfigInformation,
	 * com.ericsson.oss.itpf.security.credentialmanager
	 * .cli.service.api.CredMaServiceApiWrapper)
	 */
	@Override
	public int generateMyOwnCertificate(
			final CredentialManagerCertificate credMCertificateInfo,
			final boolean forceOverwrite, final boolean noLoop, final boolean isCheck, 
			final boolean firstDayRun) {

		int resultCode = 0;

		final CredentialManagerTBSCertificate tbsCertificate = credMCertificateInfo
				.getTbsCertificate();
		final CredentialManagerCertificateExt certificateExtensionInfo = tbsCertificate
				.getCertificateExtension();

		
		// call the remote service (via local API)
		Boolean result = false;
		try {
			result = this.serviceApi.manageCredMaCertificate(
					tbsCertificate.getEntityName(), // entityName,
					tbsCertificate.getSubjectDN(), // distinguishName,
					certificateExtensionInfo.getSubjectAlternativeName(), // subjectAltName,
					credMCertificateInfo.getEndEntityProfileName(), // entityProfileName,
					credMCertificateInfo.getKeyStores(), // keystoreInfoList,
					credMCertificateInfo.getTrustStores(), // truststoreInfoList,
					credMCertificateInfo.getCrlStores(), // crlstoreInfoList,
					certificateExtensionInfo, // certificateExtension
					forceOverwrite, noLoop, isCheck, firstDayRun);
			if (!result) {
				resultCode = -1;
			}
		} catch (final Exception e) {
		    resultCode = -9;
		    LOG.error("Caught exception "+e.getClass().getName()+" during CredMCli own certificate retrieval: result code "+resultCode);
		}

		return resultCode;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.
	 * CredMaServiceApiController
	 * #checkActionToPerform(com.ericsson.oss.itpf.security
	 * .credentialmanager.cli
	 * .service.api.ApplicationCertificateConfigInformation, boolean)
	 */
	@Override
	public List<Actions> checkActionToPerform(
			final ApplicationCertificateConfigInformation appInfo, final boolean firstDailyRun) {
		final ApplicationCertificateConfigInformation appClientConfig = appInfo;

		final ActionListManager parseOutputTot = new ActionListManager();

		try {

			for (final CredentialManagerApplication credMApplicationInfo : appClientConfig
					.getApplicationsInfo()) {

				final ActionListManager parseOutputAppl = new ActionListManager();
				for (final CredentialManagerCertificate credMCertificateInfo : credMApplicationInfo
						.getCertificates()) {

					// check if keystore or truststore already exist
					/**
					 * TOBE F.M. 28/04/2015 This check have to be reworked cause
					 * new approach for the truststore (everytime overWrited)
					 **/
					// if (this.verifyKSExists(forceOverWrite,
					// credMCertificateInfo) ||
					// this.verifyTSExists(forceOverWrite,
					// credMCertificateInfo)) {
					// throw new
					// CredentialManagerException(Logger.getLogMessage(Logger.LOG_ERROR_CREATE_KSTS));
					// }

					// prepare the parameters
					final CredentialManagerTBSCertificate tbsCertificate = credMCertificateInfo
							.getTbsCertificate();
					final CredentialManagerCertificateExt certificateExtensionInfo = tbsCertificate
							.getCertificateExtension();
					
					// call the remote service (via local API)

					try {
						CheckResult managedCheck_result = new CheckResult();
						managedCheck_result = this.serviceApi.manageCheck(
								tbsCertificate.getEntityName(), // entityName,
								tbsCertificate.getSubjectDN(), // distinguishName
								certificateExtensionInfo
										.getSubjectAlternativeName(), // subjectAltName,
								credMCertificateInfo.getEndEntityProfileName(), // entityProfileName,
								credMCertificateInfo.getKeyStores(), // keystoreInfoList,
								credMCertificateInfo.getTrustStores(), // truststoreInfoList,
								credMCertificateInfo.getCrlStores(), // crlstoreInfoList,
								certificateExtensionInfo, // certificateExtension
								credMCertificateInfo.getCertificateChain(),
								firstDailyRun);
						// New List<Actions> for one certificate has built
						parseOutputAppl.addListActionsNoDuplicate(CreateActionElement
										.parseActionList(managedCheck_result,
												credMCertificateInfo.getCheckAction()));

					} catch (final Exception e) {
						e.printStackTrace();
					}
				} // end of for Certificates
                                
				// TrustOnly management
				
				if (!credMApplicationInfo.getTrustStoresOnly().isEmpty()) {
                                    System.out.println("------------TRUST ONLY in checkActionToPerform ---------");
                                    for (final CredentialManagerTrustStoreOnly trustStoreOnly : credMApplicationInfo
                                        .getTrustStoresOnly() ) {
                                
                                        System.out.println("------------"+trustStoreOnly.getTrustProfileName());  
                                        
                                        // prepare data
                                        final String trustProfileName = trustStoreOnly.getTrustProfileName();                                     
                                        // call the remote service (via local API)
                                        CheckResult managedCheck_result = new CheckResult();
                                        managedCheck_result = this.serviceApi.manageCheckTrustAndCRL(trustProfileName, 
                                                trustStoreOnly.getTrustStores(), trustStoreOnly.getCrlStores());
                                        
                                        // New List<Actions> for one certificate has built
                                        parseOutputAppl.addListActionsNoDuplicate(CreateActionElement
                                                                        .parseActionList(managedCheck_result,
                                                                                trustStoreOnly.getCheckAction()));
                                    }
				}

				parseOutputTot.addListActionsNoDuplicate(parseOutputAppl
						.getActions());

			} // end of for Applications 

		} catch (final Exception e) {
			throw new CredentialManagerException(e);
		}
		// TO ADD elaboration value to remove the duplicate fields
		return parseOutputTot.getActions();
	}

}
