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

import java.util.List;

import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredMaExternalServiceApiWrapper;
//import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import com.ericsson.oss.itpf.security.credmsapi.api.IfCertificateManagement;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.AlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.EntityNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetCertificatesByEntityNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetEndEntitiesByCategoryException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCategoryNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCertificateFormatException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReIssueLegacyXMLCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReissueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeEntityCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateStatus;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateSummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntitySummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.business.IfCertificateManagementImpl;

public class CredMaExternalServiceApiWrapperImpl implements CredMaExternalServiceApiWrapper {

    //private static final org.slf4j.Logger LOG = Logger.getLogger();

    IfCertificateManagement credMaServiceApi = new IfCertificateManagementImpl();

    /**
     * @return the credMaServiceApi
     */
    public IfCertificateManagement getCredMaServiceApi() {
        return this.credMaServiceApi;
    }

    /**
     * 
     */
    public CredMaExternalServiceApiWrapperImpl() {
        // empty constructor to allow to instantiate it
    }

    /**
     * 
     * @return
     */
    @Override
    public String getCredentialManagerInterfaceVersion() {
        return this.credMaServiceApi.getCredentialManagerInterfaceVersion();
    }

    //
    // the following methods are for test purpose only
    //

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api. CredMaServiceApiWrapper#getEndEntitiesByCategory(java.lang.String)
     */
    @Override
    public List<EntitySummary> getEndEntitiesByCategory(final String category) throws GetEndEntitiesByCategoryException, InvalidCategoryNameException {

        return this.credMaServiceApi.getEndEntitiesByCategory(category);
    }

    /**
     * 
     * @param entityInfo
     * @param ksInfo
     * @return
     * @throws IssueCertificateException
     * @throws InvalidCertificateFormatException
     * @throws EntityNotFoundException
     */
    @Override
    public Boolean issueCertificateForENIS(final EntityInfo entityInfo, final KeystoreInfo ksInfo) throws IssueCertificateException, EntityNotFoundException, InvalidCertificateFormatException,
            OtpNotValidException, OtpExpiredException {

        return this.credMaServiceApi.issueCertificate(entityInfo, ksInfo);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api. CredMaExternalServiceApiWrapper #reIssueCertificate(com.ericsson.oss.itpf.security .credmsapi.api.model.EntityInfo,
     * com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo, com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason)
     */
    @Override
    public Boolean reIssueCertificate(final EntityInfo entityInfo, final KeystoreInfo ksInfo, final CrlReason revocationReason) throws ReissueCertificateException, EntityNotFoundException,
            InvalidCertificateFormatException, OtpNotValidException, OtpExpiredException {
        return this.credMaServiceApi.reIssueCertificate(entityInfo, ksInfo, revocationReason);
    }

    @Override
    public Boolean revokeCertificate(final EntityInfo entityInfo, final CrlReason revocationReason) throws RevokeCertificateException, EntityNotFoundException {
        return this.credMaServiceApi.revokeCertificate(entityInfo, revocationReason);
    }

    /**
     * 
     * @param entityName
     * @param entityType
     * @param certificateStatus
     * @return List<CertificateSummary>
     * @throws CertificateNotFoundException
     * @throws GetCertificatesByEntityNameException
     * @throws EntityNotFoundException
     */
    @Override
    public List<CertificateSummary> getCertificatesByEntityName(final String entityName, final EntityType entityType, final CertificateStatus... certificateStatus)
            throws CertificateNotFoundException, GetCertificatesByEntityNameException, EntityNotFoundException {
        return this.credMaServiceApi.getCertificatesByEntityName(entityName, entityType, certificateStatus);
    }

    /**
     * 
     * @param issuerDN
     * @param subjectDN
     * @param certificateSN
     * @param revocationReason
     * 
     * @return Boolean
     * 
     * @throws CertificateNotFoundException
     * @throws ExpiredCertificateException
     * @throws AlreadyRevokedCertificateException
     * @throws RevokeEntityCertificateException
     */
    @Override
    public Boolean revokeEntityCertificate(final String issuerDN, final String subjectDN, final String certificateSN, final CrlReason revocationReason) throws CertificateNotFoundException,
            ExpiredCertificateException, AlreadyRevokedCertificateException, RevokeEntityCertificateException {
        return this.credMaServiceApi.revokeEntityCertificate(issuerDN, subjectDN, certificateSN, revocationReason);
    }

    /**
     * 
     * @param entityInfo
     * @param certificateLocation
     * @param certificateChain
     * @param passwordLocation
     * @param revocationReason
     * @return
     * @throws ReIssueLegacyXMLCertificateException
     * @throws EntityNotFoundException
     * @throws OtpNotValidException
     * @throws OtpExpiredException
     */
    @Override
    public Boolean reIssueLegacyXMLCertificate(EntityInfo entityInfo, String certificateLocation, Boolean certificateChain, String passwordLocation, final CrlReason revocationReason)
            throws ReIssueLegacyXMLCertificateException, EntityNotFoundException, OtpNotValidException, OtpExpiredException {
        return this.credMaServiceApi.reIssueLegacyXMLCertificate(entityInfo, certificateLocation, certificateChain, passwordLocation, revocationReason);
    }

}
