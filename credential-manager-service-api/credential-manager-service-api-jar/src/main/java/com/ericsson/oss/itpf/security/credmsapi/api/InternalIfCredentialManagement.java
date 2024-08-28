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
package com.ericsson.oss.itpf.security.credmsapi.api;

import java.util.List;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.*;

public interface InternalIfCredentialManagement {
    

    /**
     * Method invoked by the CredM CLI, It sends a certificate request to the credential manager server for its own certificate.
     * 
     * @param entityName
     *            containing the name of the Entity, retrieved from the xml file
     * @param subjectAltName
     *            containing the alternative name of the Entity, retrieved from the xml file
     * @param entityProfileName
     *            containing the name of the profile corresponding to the Entity, retrieved from the xml file
     * @param ksInfoList
     *            representing a collection of informations related to the Key Store
     * @param tsInfoList
     *            representing a collection of informations related to the Trust Store
     * @param crlInfoList
     *            truststore data for CRL (is a truststore because is related with the trusts)
     * @param certExtension
     *            representing possible certificate extensions
     * @param noLoop
     *            boolean which determines an infinite loop researching a REST service
     * @param
     *            boolean which indicates if entity truststores need to be checked before possible rewriting
     * @param
     *            boolean which indicates if the application execution is the first of the day
     * @return A Boolean reporting the result of the operation.
     * 
     * @throws IssueCertificateException
     */
    Boolean issueCertificateRESTchannel(String entityName, String distinguishName, SubjectAlternativeNameType subjectAltName, String entityProfileName, List<KeystoreInfo> ksInfoList,
            List<TrustStoreInfo> tsInfoList, List<TrustStoreInfo> crlInfoList, CredentialManagerCertificateExtension certExtension, boolean noLoop, boolean isCheck, boolean firstDayRun) throws IssueCertificateException;

    /**
     * Method invoked by the CredM CLI, It sends a certificate request to the credential manager server.
     * 
     * @param entityName
     *            containing the name of the Entity, retrieved from the xml file
     * @param subjectAltName
     *            containing the alternative name of the Entity, retrieved from the xml file
     * @param entityProfileName
     *            containing the name of the profile corresponding to the Entity, retrieved from the xml file
     * @param ksInfoList
     *            representing a collection of informations related to the Key Store
     * @param tsInfoList
     *            representing a collection of informations related to the Trust Store
     * @param crlInfoList
     *            truststore data for CRL (is a truststore because is related with the trusts)
     * @param certExtension
     *            possible extensions for the certficate request
     * @param certificateChain
     *            boolean to request to PKI also the complete certificate chain for the generated certificate
     * @return A Boolean reporting the result of the operation.
     * 
     * @throws IssueCertificateException
     */
    Boolean issueCertificate(String entityName, String distinguishName, SubjectAlternativeNameType subjectAltName, String entityProfileName, List<KeystoreInfo> ksInfoList,
            List<TrustStoreInfo> tsInfoList, List<TrustStoreInfo> crlInfoList, CredentialManagerCertificateExtension certExtension, boolean certificateChain) throws IssueCertificateException;



    /**
     * checkAndUpdateCertificate
     * 
     * @param entityName
     * @param distinguishName
     * @param subjectAltName
     * @param entityProfileName
     * @param ksInfoList
     * @param certificateExtensionInfo
     * @param certificateChain
     * 
     * @return Boolean 
     * true = the certificate has been updated
     * false = the certificate is valid and nothing has been done
     * (if something gone wrong, an excpetion is thrown)
     * 
     * @throws IssueCertificateException
     */
    Boolean checkAndUpdateCertificate(final String entityName, final String distinguishName, final SubjectAlternativeNameType subjectAltName, final String entityProfileName,
            final List<KeystoreInfo> ksInfoList, final CredentialManagerCertificateExtension certificateExtensionInfo, final boolean certificateChain, final boolean firstDailyRun) throws IssueCertificateException;

    /**
     * checkAndUpdateTrusts
     * (for trustProfile)
     * 
     * @param trustProfileName
     * @param tsInfoList
     * @return
     * @throws IssueCertificateException
     */
    public Boolean checkAndUpdateTrustsTP(final String trustProfileName, final List<TrustStoreInfo> tsInfoList) throws IssueCertificateException;

        
    /**
     * checkAndUpdateTrusts
     * (version for entity)
     * 
     * @param entityName
     * @param distinguishName
     * @param altName
     * @param entityProfileName
     * @param ksInfoList
     * @param tsInfoList
     * @param crlInfoList
     * @param certificateExtension
     * @param isOwn
     * 
     * @return boolean
     * true = the truststore has been updated
     * false = the truststore is valid and nothing has been done
     * (if something gone wrong, an excpetion is thrown)
     * 
     * @throws IssueCertificateException
     */
    Boolean checkAndUpdateTrusts(final String entityName, final String entityProfileName, 
    		            final List<TrustStoreInfo> tsInfoList, boolean isOwn) throws IssueCertificateException;


    
    /**
     * checkAndUpdateCRL
     * 
     * @param entityName
  
     * @param crlInfoList
     * @param forceUpdate
     * 
     * @return boolean
     * true = the truststore has been updated
     * false = the truststore is valid and nothing has been done
     * (if something gone wrong, an exception is thrown)
     * 
     * @throws IssueCertificateException
     */
    Boolean checkAndUpdateCRL(final String entityName, final List<TrustStoreInfo> crlInfoList,
            final boolean forceUpdate) throws IssueCertificateException;


    /**
     * checkAndUpdateCRL
     * (using TrustProfile)
     * 
     * @param entityName
  
     * @param crlInfoList
     * @param forceUpdate
     * 
     * @return boolean
     * true = the truststore has been updated
     * false = the truststore is valid and nothing has been done
     * (if something gone wrong, an exception is thrown)
     * 
     * @throws IssueCertificateException
     */
    Boolean checkAndUpdateCRL_TP(final String trustProfileName, final List<TrustStoreInfo> crlInfoList,
            final boolean forceUpdate) throws IssueCertificateException; 

}
