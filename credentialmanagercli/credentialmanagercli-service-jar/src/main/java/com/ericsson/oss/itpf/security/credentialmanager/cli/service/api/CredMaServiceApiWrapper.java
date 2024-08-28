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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

import java.util.List;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.CheckResult;

/**
 * 
 * Define the interface of external environment from where credential manager CLI will fetch the certificates
 * 
 */
public interface CredMaServiceApiWrapper {

    //	enum REMOTE_ENVIROMMENT {
    //		CREDMAN_SERVICE_API, MOCKED_API, SERVICE_API_FOR_TEST
    //	};

    /**
     * @param entityName
     * @param distinguishName
     * @param subjectAltName
     * @param entityProfileName
     * @param keystoreInfoList
     * @param truststoreInfoList
     * @param crlstoreInfoList
     * @param certificateExtension
     * @param forceOverWrite
     * @param certficateChain
     * @return
     * @throws CredentialManagerException
     */
    Boolean manageCertificateAndTrust(String entityName, String distinguishName, CredentialManagerSubjectAltName subjectAltName, String entityProfileName,
            List<CredentialManagerKeyStore> keystoreInfoList, List<CredentialManagerTrustStore> truststoreInfoList, List<CredentialManagerTrustStore> crlstoreInfoList,
            CredentialManagerCertificateExt certificateExtension, boolean certficateChain, boolean forceOverWrite) throws CredentialManagerException;

    /**
     * 
     * @param entityName
     * @param distinguishName
     * @param subjectAltName
     * @param entityProfileName
     * @param keystoreInfoList
     * @param truststoreInfoList
     * @param crlstoreInfoList
     * @param certificateExtension
     * @param noLoop
     * @param isCheck
     * @param firstDayRun
     * @return
     * @throws CredentialManagerException
     */
    Boolean manageCredMaCertificate(String entityName, String distinguishName, CredentialManagerSubjectAltName subjectAltName, String entityProfileName,
            List<CredentialManagerKeyStore> keystoreInfoList, List<CredentialManagerTrustStore> truststoreInfoList, List<CredentialManagerTrustStore> crlstoreInfoList,
            CredentialManagerCertificateExt certificateExtension, boolean forceOverWrite, boolean noLoop, boolean isCheck, boolean firstDayRun) throws CredentialManagerException;

    /**
     * @param entityName
     * @param subjectDN
     * @param subjectAlternativeName
     * @param endEntityProfileName
     * @param keyStores
     * @param trustStores
     * @param crlStores
     * @param certificateExtensionInfo
     * @param forceOverWrite
     * @return
     */
    CheckResult manageCheck(String entityName, String subjectDN, CredentialManagerSubjectAltName subjectAlternativeName, String endEntityProfileName, List<CredentialManagerKeyStore> keyStores,
            List<CredentialManagerTrustStore> trustStores, List<CredentialManagerTrustStore> crlStores, CredentialManagerCertificateExt certificateExtensionInfo, boolean certificateChain, boolean firstDailyRun);

    /**
     * 
     * @param trustProfileName
     * @param truststoreInfoList
     * @param crlstoreInfoList
     * @return
     * @throws CredentialManagerException
     */
    CheckResult manageCheckTrustAndCRL( String trustProfileName, 
             List<CredentialManagerTrustStore> truststoreInfoList,  List<CredentialManagerTrustStore> crlstoreInfoList)
            throws CredentialManagerException;

    
}
