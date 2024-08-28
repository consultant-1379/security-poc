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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

/**
 * This is an interface for External CA certificate management service and it provides below operations.
 * <ul>
 * <li>Importing certificate for External CA entities.</li>
 * <li>Remove any reference to an ExtCA.</li>
 * </ul>
 */
@EService
@Remote
public interface ExtCACertificateManagementService extends CertificateManagementService {

    /**
     * Imports an External CA certificate into the PKI system, checks for IssuerCA, if present sets IssuerCA to certificate else ExternalCredentialMgmtServiceException *is thrown.
     *
     * @param extCAName
     *            name of the External CA for which certificate needs to be imported.
     * @param x509Certificate
     *            X509Certificate object containing certificate data.
     * @param enableRFCValidation
     *            if the validation with RFC5280 of the certificate is enabled.
     * @throws CertificateFieldException
     *             Thrown in case of parse error on generate certificate.
     * @throws CertificateNotFoundException
     *             Thrown when external ca certificate is not found in database.
     * @throws ExternalCAAlreadyExistsException
     *             Thrown in case the CA name is already used for another CA or External CA.
     * @throws ExternalCANotFoundException
     *             Throws when the External CA is not found in database.
     * @throws ExternalCredentialMgmtServiceException
     *             Thown when internal db error occurs
     * @throws MissingMandatoryFieldException
     *             Throws in case of missing mandatory fields
     */
    void importCertificate(final String extCAName, final X509Certificate x509Certificate, final boolean enableRFCValidation) throws CertificateFieldException, CertificateNotFoundException,
            ExternalCAAlreadyExistsException, ExternalCANotFoundException, ExternalCredentialMgmtServiceException, MissingMandatoryFieldException;

    /**
     * Imports an External CA certificate into the PKI system,checks for issuerCA if present sets IssuerCA to certificate else skips chain validation and also Issuer *will not be set to certificate.
     *
     * @param extCAName
     *            name of the External CA for which certificate needs to be imported.
     * @param x509Certificate
     *            X509Certificate object containing certificate data.
     * @param enableRFCValidation
     *            if the validation with RFC5280 of the certificate is enabled.
     * 
     * @throws CertificateFieldException
     *             Thrown in case of parse error on generate certificate.
     * @throws ExternalCAAlreadyExistsException
     *             Thrown in case the CA name is already used for another CA or External CA.
     * @throws ExternalCredentialMgmtServiceException
     *             Thown when internal db error occurs
     * @throws MissingMandatoryFieldException
     *             Throws in case of missing mandatory fields
     */
    void forceImportCertificate(final String extCAName, final X509Certificate x509Certificate, final boolean enableRFCValidation) throws CertificateFieldException, ExternalCAAlreadyExistsException,
            ExternalCredentialMgmtServiceException, MissingMandatoryFieldException;

    /**
     * This method will remove all the certificates related to an external CA.
     *
     * @param extCAName
     *            name of the External CA for which Certificates and CRLs has to remove.
     * @throws MissingMandatoryFieldException
     *             Thrown in case extCAName is null or empty.
     * @throws ExternalCANotFoundException
     *             Thrown in case the given external CA does not exist
     * @throws ExternalCAInUseException
     *             Thrown in case the given external CA is used in a Trust Profile.
     * @throws ExternalCACRLsExistException
     *             Thrown in case the given external CA has some CRLs associated.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     */
    void remove(final String extCAName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCAInUseException, ExternalCACRLsExistException,
            ExternalCredentialMgmtServiceException;

    /**
     * This method will export the certificate (and its chain) related to an external CA. The latest imported certificate is returned if the serial number is empty.
     * 
     * @param extCAName
     *            name of the External CA.
     * @param serialNumber
     *            serialNumber of the certificate to export.
     * @param chain
     *            if chain is true the chain of certificate is returned.
     * @return a chain of X509Certificate of the External CA.
     * @throws CertificateNotFoundException
     *             Thrown in case no certificate is associated with the External CA.
     * @throws ExternalCANotFoundException
     *             Thrown in case the given external CA does not exist.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws MissingMandatoryFieldException
     *             Thrown in case extCAName is null or empty.
     */
    List<X509Certificate> exportCertificate(final String extCAName, final String serialNumber, final boolean chain) throws CertificateNotFoundException, ExternalCANotFoundException,
            ExternalCredentialMgmtServiceException, MissingMandatoryFieldException;
}
