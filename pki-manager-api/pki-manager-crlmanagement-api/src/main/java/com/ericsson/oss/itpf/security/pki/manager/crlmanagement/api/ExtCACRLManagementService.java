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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api;

import java.util.List;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

/**
 * This is an interface for External CA CRL management service and it provides below operations.
 * <ul>
 * <li>Add External CRL information of an External CA entity.</li>
 * <li>List External CRL information of an External CA entity.</li>
 * </ul>
 */
@EService
@Remote
public interface ExtCACRLManagementService extends CRLManagementService {

    /**
     * This method add or update an ExternalCRLInfo associated to an External CA.
     *
     * @param extCAName
     *            name of the External CA for which ExternalCRLInfo has to be related.
     * @param externalCRLInfo
     *            The {@link ExternalCRLInfo} information. The id is not considered.
     * @throws MissingMandatoryFieldException
     *             Thrown in case extCAName is null or empty externalCRLInfo is empty.
     * @throws ExternalCANotFoundException
     *             Thrown in case the given external CA does not exist.
     * @throws ExternalCRLException
     *             Thrown in case the external CRL is empty or some error occured during the encode.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     */
    void addExternalCRLInfo(final String extCAName, ExternalCRLInfo externalCRLInfo)
            throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException;

    /**
     * This method configures the ExternalCRLInfo associated to an External CA.
     *
     * @param extCAName
     *            name of the External CA for which ExternalCRLInfo has to be related.
     * @param isCrlAutoUpdateEnabled
     *            enable/disable the automatic update of the crl url.
     * @param crlAutoUpdateTimer
     *            number of days to update a crl url. 
     *            If 0 the crl NextUpdate value will be used to update automatically the crl. 
     * @throws MissingMandatoryFieldException
     *             Thrown in case extCAName is null or empty crlAutoUpdateTimer is negative value.
     * @throws ExternalCANotFoundException
     *             Thrown in case the given external CA does not exist.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     */
    void configExternalCRLInfo(final String extCAName, final Boolean isCrlAutoUpdateEnabled, final Integer crlAutoUpdateTimer)
            throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCredentialMgmtServiceException;
    
    /**
     * Returns a list of ExternalCRLInfo issued for the External CA
     *
     * @param extCAName
     *            name of the External CA
     * @return list of ExternalCRLInfo associated to the given External CA
     * @throws MissingMandatoryFieldException
     *             Thrown in case extCAName is null or empty.
     * @throws ExternalCRLNotFoundException
     *             Thrown if CRL not found for the given External CA.
     * @throws ExternalCANotFoundException
     *             Thrown in case the given external CA does not exist.
     * @throws ExternalCRLEncodedException
     *             Thrown in case of error during encoding CRL.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown in case of any internal database failures.
     */
    List<ExternalCRLInfo> listExternalCRLInfo(final String extCAName)
            throws MissingMandatoryFieldException, ExternalCRLNotFoundException, ExternalCANotFoundException, ExternalCredentialMgmtServiceException, ExternalCRLEncodedException;

    /**
     * This method remove the ExternalCRLInfo associated to an External CA for a given issuer name.
     * If issuerName is null all ExternalCRLInfo associated to an External CA are removed.
     *
     * @param extCAName
     *            name of the External CA for which ExternalCRLInfo has to be related.
     * @param issuerName
     *            name of the issuer for CRL for External CA.
     * @throws MissingMandatoryFieldException
     *             Thrown in case extCAName is null or empty.
     * @throws ExternalCANotFoundException
     *             Thrown in case the given external CA does not exist.
     * @throws ExternalCRLNotFoundException
     *             Thrown in case the given CRL for External CA is not found.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     */
    void removeExtCRL(final String extCAName, final String issuerName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCRLNotFoundException, ExternalCredentialMgmtServiceException;

    /**
     * This method remove all ExternalCRLInfo associated to an External CA.
     * 
     * @param extCAName
     *           name of the External CA for which ExternalCRLInfo has to be related.
     * @throws MissingMandatoryFieldException
     *             Thrown in case extCAName is null or empty.
     * @throws ExternalCANotFoundException
     *             Thrown in case the given external CA does not exist.
     * @throws ExternalCAInUseException
     *             Thrown in case the given external CA is in use.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     */
    void remove(final String extCAName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCAInUseException, ExternalCredentialMgmtServiceException;

}
