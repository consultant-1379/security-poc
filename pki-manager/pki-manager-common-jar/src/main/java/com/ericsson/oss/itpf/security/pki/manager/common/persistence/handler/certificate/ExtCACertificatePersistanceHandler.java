/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateConversionException;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.extcertificate.ExtCertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerCertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * This class is responsible for handling the operations on external CA certificates.
 *
 * @author tcsmanp
 *
 */

public class ExtCACertificatePersistanceHandler {

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    ExtCertificateModelMapper extCertificateModelMapper;

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityPersistenceHandler<CAEntity> caEntityPersistenceHandler;

    @Inject
    SystemRecorder systemRecorder;

    private static final String getAllExternalCACertificatesQuery = "select c from CertificateData c where c.id in (select p.id from CAEntityData ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.externalCA = true and p.status=1)";
    private static final String CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS_EXTERNAL_CA = "select c from CertificateData c where c.id in(select p.id from CAEntityData ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and p.status in(:status) and ec.externalCA = true) ORDER BY c.id DESC";
    private static final String FETCH_CAENTITY_BY_CERTIFICATE_ID = "select ec from CAEntityData ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE  p.id in(:certificate_id) and ec.externalCA = true ";

    /**
     * This method populates and returns all the external CA Certificates from database.
     */
    public List<CertificateData> populateExternalCACertificates() throws CertificateServiceException {
        final List<CertificateData> allExternalCACertificateDatas = getAllExternalCACertificates();
        return allExternalCACertificateDatas;
    }

    /**
     * Gets the list of all external CA certificates.
     *
     * @return {@link CertificateData List}
     * @throws CertificateServiceException
     *             Thrown in case any database issue occurred.
     */
    public List<CertificateData> getAllExternalCACertificates() throws CertificateServiceException {
        try {
            final Query query = persistenceManager.getEntityManager().createQuery(getAllExternalCACertificatesQuery);

            final List<CertificateData> certificateDatas = query.getResultList();
            if (!ValidationUtils.isNullOrEmpty(certificateDatas)) {
                return certificateDatas;
            } else {
                return null;
            }
        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.EXTERNAL_CA_CERTIFICATE_NOT_FOUND, persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.EXTERNAL_CA_CERTIFICATE_NOT_FOUND, persistenceException);
        }
    }

    /**
     * This method updates chain of issuerCertificate. If issuerCertificate is Root CA then not building chain.
     *
     * @param X509Certificate
     *            The X509 certificate based on which certificate chain will be build.
     *
     * @throws CertificateNotFoundException
     *             Thrown when the issuer certificate is not found.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while getting the issuer certificate.
     */
    public void updateIssuerCertificateChain(final X509Certificate x509Certificate) throws CertificateNotFoundException, CertificateConversionException {

        try {
            final X500Name issuerDnOfCertificate = new JcaX509CertificateHolder(x509Certificate).getIssuer();
            final X500Name subjectDnOfCertificate = new JcaX509CertificateHolder(x509Certificate).getSubject();

            if (!issuerDnOfCertificate.equals(subjectDnOfCertificate)) {
                updateIssuerCertificateAndChainBuild(x509Certificate);
            }

        } catch (final CertificateEncodingException certificateEncodingException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_FAILED_WHILE_CHAIN_VALIDATION, certificateEncodingException.getMessage());
            throw new CertificateServiceException(ErrorMessages.CERTIFICATE_ENCODING_FAILED_WHILE_CHAIN_VALIDATION, certificateEncodingException);
        }
    }

    /**
     * This method updates chain of issuerCertificate relations from external CA certificate till Root CA
     *
     * @param X509Certificate
     *            The X509 certificate based on which certificate chain will be build.
     *
     * @throws CertificateNotFoundException
     *             Thrown when the Issuer Certificate is not found.
     * @throws CertificateServiceException
     *             Thrown when the Issuer Certificate is corrupted and failed to obtain
     */
    private void updateIssuerCertificateAndChainBuild(final X509Certificate x509Certificate) throws CertificateNotFoundException, CertificateServiceException {

        try {
            final CertificateData issuerCertificateData = getIssuerCertificateData(x509Certificate);
            if (issuerCertificateData == null) {
                logger.error(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
                throw new CertificateNotFoundException(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
            }
            updateIssuerCertificateData(getCertificateData(x509Certificate), issuerCertificateData);

            final X509Certificate issuerCertificate = CertificateUtility.getCertificateFromByteArray(issuerCertificateData.getCertificate());

            final X500Name issuerDnOfIssuerCertificate = new JcaX509CertificateHolder(issuerCertificate).getIssuer();
            final X500Name subjectDnOfIssuerCertificate = new JcaX509CertificateHolder(issuerCertificate).getSubject();

            if (!issuerDnOfIssuerCertificate.equals(subjectDnOfIssuerCertificate)) {
                updateIssuerCertificateAndChainBuild(issuerCertificate);
            }

        } catch (final CertificateEncodingException certificateEncodingException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_FAILED_WHILE_CHAIN_VALIDATION, certificateEncodingException.getMessage());
            throw new CertificateServiceException(ErrorMessages.CERTIFICATE_ENCODING_FAILED_WHILE_CHAIN_VALIDATION, certificateEncodingException);
        }
    }

    private void updateIssuerCertificateData(final CertificateData certificateData, final CertificateData issuerCertificateData) throws CertificateServiceException {

        try {
            certificateData.setIssuerCertificate(issuerCertificateData);
            persistenceManager.updateEntity(certificateData);

        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        }
    }

    /**
     * This method returns issuer CertificateData for provided X509Certificate if match authorityKeyIdentifier To SubjectKeyKeyIdentifier.
     *
     * @param x509Certificate
     *            The X509 certificate object .
     * @return CertificateData object.
     *
     */
    public CertificateData getIssuerCertificateData(final X509Certificate x509Certificate) throws CertificateServiceException, CertificateConversionException {
        if (populateExternalCACertificates() != null) {
            for (final CertificateData certificate : populateExternalCACertificates()) {
                if (matchAuthKeyToSubjectKey(x509Certificate, certificate)) {
                    return certificate;
                }
            }
        }
        return null;
    }

    /**
     * This method returns CertificateData for provided X509Certificate if match SubjectKeyKeyIdentifier.
     *
     * @param x509Certificate
     *            The X509 certificate object .
     * @return CertificateData object.
     * @throws CertificateNotFoundException
     *             Thrown when external ca certificate is not found in database.
     */
    public CertificateData getCertificateData(final X509Certificate x509Certificate) throws CertificateServiceException, CertificateNotFoundException {
        final List<CertificateData> allExternalCACertificateDatas = populateExternalCACertificates();
        if (allExternalCACertificateDatas == null) {
            logger.error(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
            throw new CertificateNotFoundException(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
        }

        for (final CertificateData certificate : allExternalCACertificateDatas) {
            if (matchSubjectKeyToSubjectKey(x509Certificate, certificate)) {
                return certificate;
            }
        }
        throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND);
    }

    /**
     * This method returns issuer X509Certificate for provided X509Certificate if match authorityKeyIdentifier To SubjectKeyKeyIdentifier.
     *
     * @param x509Certificate
     *            The X509 certificate object .
     * @return X509Certificate object.
     * @throws CertificateNotFoundException
     *             Thrown when external ca certificate is not found in database.
     */
    public X509Certificate getIssuerX509Certificate(final X509Certificate x509Certificate) throws CertificateServiceException, CertificateNotFoundException {
        final List<CertificateData> allExternalCACertificateDatas = populateExternalCACertificates();
        if (allExternalCACertificateDatas == null) {
            logger.error(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
            throw new CertificateNotFoundException(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
        }
        for (final CertificateData issuerCertificateData : allExternalCACertificateDatas) {
            if (matchAuthKeyToSubjectKey(x509Certificate, issuerCertificateData)) {
                return CertificateUtility.getCertificateFromByteArray(issuerCertificateData.getCertificate());
            }
        }
        throw new CertificateNotFoundException(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
    }

    private boolean matchSubjectKeyToSubjectKey(final X509Certificate inputCertificate, final CertificateData certificateDataToMatch) throws CertificateConversionException {

        final X509Certificate certificateToMatch = CertificateUtility.getCertificateFromByteArray(certificateDataToMatch.getCertificate());

        final byte[] subjectKeyIdOfCert = inputCertificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        final ASN1OctetString akiOc = ASN1OctetString.getInstance(subjectKeyIdOfCert);
        final SubjectKeyIdentifier subjectKeyIdentifierOfCert = SubjectKeyIdentifier.getInstance(akiOc.getOctets());

        final byte[] subjectKeyIdOfIssuerCert = certificateToMatch.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        final ASN1OctetString skiOc = ASN1OctetString.getInstance(subjectKeyIdOfIssuerCert);
        final SubjectKeyIdentifier subjectKeyIdentifierOfCertToMatch = SubjectKeyIdentifier.getInstance(skiOc.getOctets());

        return (Arrays.equals(subjectKeyIdentifierOfCert.getKeyIdentifier(), subjectKeyIdentifierOfCertToMatch.getKeyIdentifier()));
    }

    private boolean matchAuthKeyToSubjectKey(final X509Certificate inputCertificate, final CertificateData certificateDataToMatch) throws CertificateConversionException {

        final X509Certificate certificateToMatch = CertificateUtility.getCertificateFromByteArray(certificateDataToMatch.getCertificate());

        final byte[] authorityKeyIdOfCert = inputCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (authorityKeyIdOfCert == null) {
            return false;
        }
        final ASN1OctetString akiOc = ASN1OctetString.getInstance(authorityKeyIdOfCert);
        final AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(akiOc.getOctets());

        final byte[] subjectKeyIdOfIssuerCert = certificateToMatch.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if (subjectKeyIdOfIssuerCert == null) {
            return false;
        }
        final ASN1OctetString skiOc = ASN1OctetString.getInstance(subjectKeyIdOfIssuerCert);
        final SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(skiOc.getOctets());

        return (Arrays.equals(authorityKeyIdentifier.getKeyIdentifier(), subjectKeyIdentifier.getKeyIdentifier()));
    }

    /**
     * This method validates the certificate chain and check if there are any Revoked or Expired certificates in chain.
     *
     * @param X509Certificate
     *            The X509 certificate object.
     * @throws CertificateNotFoundException
     *             Thrown when external ca certificate is not found in database.
     * @throws IssuerCertificateRevokedException
     *             Thrown when the certificate in the chain gets revoked.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain is revoked.
     */
    public void validateCertificateChain(final X509Certificate x509Certificate) throws CertificateNotFoundException, CertificateServiceException, IssuerCertificateRevokedException,
            ExpiredCertificateException, RevokedCertificateException {

        final CertificateData certificateData = getCertificateData(x509Certificate);
        certificatePersistenceHelper.validateCertificateChain(certificateData, EnumSet.of(CertificateStatus.REVOKED, CertificateStatus.EXPIRED));
    }

    /**
     * Get the certificate data list of given entity.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @param certificateStatuses
     *            Retrieve the certificates which matches the given statuses.
     * @return List of certificate data objects.
     *
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public List<CertificateData> getCertificateDatasForExtCA(final String caEntityName, final CertificateStatus... certificateStatuses) throws PersistenceException {

        final List<Integer> certificateStatusIds = new ArrayList<Integer>();
        for (final CertificateStatus certificateStatus : certificateStatuses) {
            certificateStatusIds.add(certificateStatus.getId());
        }

        final Query query = persistenceManager.getEntityManager().createQuery(CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS_EXTERNAL_CA);
        query.setParameter("name", caEntityName);
        query.setParameter("status", certificateStatusIds);

        final List<CertificateData> certificateDatas = query.getResultList();
        if (ValidationUtils.isNullOrEmpty(certificateDatas)) {
            return null;
        }

        return certificateDatas;

    }

    /**
     * Get the certificate list of given entity.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @param certificateStatuses
     *            Retrieve the certificates which matches the given statuses.
     * @return List of certificate data objects.
     *
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     * @throws IOException
     * @throws CertificateException
     */
    public List<Certificate> getCertificatesForExtCA(final String caEntityName, final CertificateStatus... certificateStatuses) throws CertificateException, IOException, PersistenceException {
        return extCertificateModelMapper.toObjectModel(getCertificateDatasForExtCA(caEntityName, certificateStatuses));
    }

    /**
     * This method is used to set issuer to CertificateData.
     *
     * @param caEntityData
     *            IssuerCA which has to be set.
     * @param certificateData
     *            to which issuer and subject has to be set.
     * @param isChainRequired
     *            is true if issuer certificate has to be present in the system.
     *
     * @throws CANotFoundException
     *             is thrown when external ca is not found in database.
     * @throws CertificateNotFoundException
     *             is thrown when external ca certificate is not found in database.
     * @throws PersistenceException
     *             is thrown if any error occurs while fetching data from database.
     */

    public void setIssuerToExtCertificate(final CAEntityData caEntityData, final CertificateData certificateData, final boolean isChainRequired) throws CANotFoundException,
            CertificateNotFoundException, PersistenceException {
        if (caEntityData.getCertificateAuthorityData().isRootCA()) {
            certificateData.setIssuerCA(caEntityData);
        } else {
            final CertificateData issuerCertificateData = getIssuerCertificateData(CertificateUtility.getCertificateFromByteArray(certificateData.getCertificate()));

            if (issuerCertificateData != null) {
                final CAEntityData issuerCAEntity = getCAEntityData(issuerCertificateData.getId());
                if (issuerCAEntity == null) {
                    logger.error(ErrorMessages.ISSUER_CA_NOT_FOUND);
                    throw new CANotFoundException(ErrorMessages.ISSUER_CA_NOT_FOUND);
                }

                certificateData.setIssuerCA(issuerCAEntity);
                return;
            }

            if (isChainRequired) {
                logger.error(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
                throw new CertificateNotFoundException(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
            } else {
                systemRecorder.recordEvent("EXTCA_SERVICE", EventLevel.COARSE, "EXTCA_SERVICE.FORCE_CERTIFICATE_IMPORT", caEntityData.getCertificateAuthorityData().getName(),
                        ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
                logger.info(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND);
                return;
            }
        }
    }

    /**
     * This method is used to fetch caEntityData based on given CertificateId.
     *
     * @param CertificateID
     *            for whuch CaenityData has to be fetched.
     * @return caEntityData
     * @throws PersistenceException
     *             is thrown if any error occurs while retreiving data from database.
     */
    public CAEntityData getCAEntityData(final long CertificateID) throws PersistenceException {
        CAEntityData caEntityData = null;
        final Query query = persistenceManager.getEntityManager().createQuery(FETCH_CAENTITY_BY_CERTIFICATE_ID);
        query.setParameter("certificate_id", CertificateID);
        caEntityData = (CAEntityData) query.getSingleResult();
        return caEntityData;
    }

    /**
     * Get CAEntityData of given CAEntity.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @return caEntityData
     * @throws CANotFoundException
     *             Throws in case of CAEntity not found in the database.
     * @throws PersistenceException
     *             Throws in case of any problem occurs while doing database operations.
     */
    public CAEntityData getCAEntity(final String caEntityName) throws CANotFoundException, CertificateServiceException {

        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(caEntityName);
        caEntity.setCertificateAuthority(certificateAuthority);
        CAEntityData caEntityData = null;

        try {
            caEntityData = caEntityPersistenceHandler.getCAEntitydata(caEntity);

        } catch (final EntityNotFoundException | InvalidEntityAttributeException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            throw new CANotFoundException(ErrorMessages.INTERNAL_ERROR, exception);
        }  catch (final EntityServiceException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, exception);
        }
        return caEntityData;

    }

    /**
     *
     * This method is used to set Issuer and Subject for ExtCertificate for existing certificates in the system.
     *
     * @param entityName
     *            update the certificates which matches the given entityName.
     * @param certificates
     *            update the certificates.
     *
     * @throws CANotFoundException
     *             is thrown if ca is not found in the database.
     * @throws CertificateException
     *             is thrown in case Certificate is not in proper format
     * @throws CertificateNotFoundException
     *             Thrown when external ca certificate is not found in database.
     * @throws IOException
     *             is thrown in case of any encoding exception while converting certificate to byteArray.
     * @throws PersistenceException
     *             is thrown in case of any internal db error.
     */
    public void updateIssuerAndSubjectForExtCertificate(final String caEntityName, final List<Certificate> certificates) throws CANotFoundException, CertificateException,
            CertificateNotFoundException, CertificateServiceException, IOException, PersistenceException {

        final CAEntityData caEntityData = getCAEntity(caEntityName);
        if (caEntityData.isExternalCA()) {
            for (final Certificate certificate : certificates) {
                final CertificateData certificateData = extCertificateModelMapper.fromObjectModel(certificate);
                if (certificate.getIssuer() == null) {
                    setIssuerToExtCertificate(caEntityData, certificateData, true);
                }
                if (certificate.getSubject() == null) {
                    certificateData.setSubjectDN(caEntityData.getCertificateAuthorityData().getSubjectDN());
                }
                persistenceManager.updateEntity(certificateData);
                certificates.remove(certificate);
                certificates.add(extCertificateModelMapper.toCertificate(certificateData));
            }
        }
    }

}
