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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmCategory;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLGenerationInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

/**
 * This abstract class contains common methods that are used by all profile model mappers to populate some objects from database. This class is extended by all profile model mappers.
 *
 *
 */
public abstract class AbstractModelMapper implements ModelMapper {
    private final static String CA_NAME_PATH = "certificateAuthorityData.name";
    private static final String NAME_PATH = "name";
    private static final String TYPE_PATH = "type";
    private static final String KEYSIZE_PATH = "keySize";
    private static final String SUPPORTED_PATH = "supported";
    private static final String CATEGORIES_PATH = "categories";

    @Inject
    protected Logger logger;

    @Inject
    protected PersistenceManager persistenceManager;

    @Inject
    protected CRLGenerationInfoMapper cRLGenerationInfoMapper;
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * This method returns algorithm if any found in DB with given name, given keysize, type as ASYMMETRIC_KEY_ALGORITHM and supported as true
     *
     * @param name
     * @param keySize
     * @return AlgorithmData
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors occur.
     */
    public AlgorithmData populateKeyGenerationAlgorithm(final String name, final Integer keySize) throws PKIConfigurationServiceException {
        final Map<String, Object> input = new HashMap<String, Object>();
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.OTHER.getId());
        final Boolean result = Boolean.valueOf(true);

        input.put(NAME_PATH, name);
        input.put(TYPE_PATH, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.getId());
        input.put(KEYSIZE_PATH, keySize);
        input.put(SUPPORTED_PATH, result);
        input.put(CATEGORIES_PATH, categories);

        AlgorithmData algorithmData = null;
        try {
            algorithmData = persistenceManager.findEntityWhere(AlgorithmData.class, input);
        } catch (final PersistenceException e) {
            logger.error("SQL Exception occurred while retrieving CAs in DB {}", e.getMessage());
            throw new PKIConfigurationServiceException("Occured in retrieving CAs", e);
        }
        return algorithmData;
    }

    /**
     * This method returns algorithm if any found in DB with given name, given keysize, type as SIGNATURE_ALGORITHM and supported as true
     *
     * @param name
     * @param keySize
     * @return AlgorithmData
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors occur.
     */
    public AlgorithmData populateSignatureAlgorithm(final String name) throws PKIConfigurationServiceException {
        final Map<String, Object> input = new HashMap<String, Object>();
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.OTHER.getId());
        final Boolean result = Boolean.valueOf(true);

        input.put(NAME_PATH, name);
        input.put(TYPE_PATH, AlgorithmType.SIGNATURE_ALGORITHM.getId());
        input.put(SUPPORTED_PATH, result);
        input.put(CATEGORIES_PATH, categories);

        AlgorithmData algorithmData = null;
        try {
            algorithmData = persistenceManager.findEntityWhere(AlgorithmData.class, input);
        } catch (final PersistenceException e) {
            logger.error("SQL Exception occurred while retrieving CAs in DB {}", e.getMessage());
            throw new PKIConfigurationServiceException("Occured in retrieving CAs", e);
        }
        return algorithmData;
    }

    /**
     * This method returns algorithm if any found in DB with given name, given keysize, type as SIGNATURE_ALGORITHM and supported as true
     *
     * @param name
     * @param keySize
     * @return AlgorithmData
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors occur.
     */
    public AlgorithmData populateKeyIdentifierAlgorithmData(final String name) throws PKIConfigurationServiceException {
        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.KEY_IDENTIFIER.getId());
        final Boolean result = Boolean.valueOf(true);

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(NAME_PATH, name);
        input.put(SUPPORTED_PATH, result);
        input.put(CATEGORIES_PATH, categories);


        AlgorithmData algorithmData = null;
        try {
            algorithmData = persistenceManager.findEntityWhere(AlgorithmData.class, input);
        } catch (final PersistenceException e) {
            logger.error("SQL Exception occurred while retrieving CAs in DB {}", e.getMessage());
            throw new PKIConfigurationServiceException("Occured in retrieving CAs", e);
        }
        return algorithmData;
    }

    /**
     * This method fetches EntityProfile with given name from DB
     *
     * @param entityProfileName
     * @return EntityProfileData
     * @throws ProfileServiceException
     *             thrown when any internal Database errors occur.
     */
    public EntityProfileData populateEntityProfileData(final String entityProfileName) throws ProfileServiceException {
        EntityProfileData entityProfileData = new EntityProfileData();
        try {
            entityProfileData = persistenceManager.findEntityByName(EntityProfileData.class, entityProfileName, "name");
        } catch (final PersistenceException e) {
            logger.error("SQL Exception occurred while retrieving EntityProfile from DB {}", e.getMessage());
            throw new ProfileServiceException("Occured in retrieving EntityProfile", e);
        }

        return entityProfileData;
    }

    /**
     * This method maps the list of JPA Entities to its corresponding API Model list.
     *
     * @param dataModelList
     *            {@link java.util.List} of {@link CAEntity}/{@link Entity}
     * @return {@link java.util.List} of {@link CAEntityData}/{@link EntityData}
     *
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping profile
     */
    @Override
    public <T, E> List<T> toAPIModelList(final List<E> dataModelList) throws CANotFoundException, InvalidEntityAttributeException, InvalidProfileAttributeException {
        final List<T> aPIModelList = new ArrayList<T>();

        for (final E dataModel : dataModelList) {
            try {
                final T aPIModel = toAPIFromModel(dataModel);
                if (aPIModel != null) {
                    aPIModelList.add(aPIModel);
                }
            } catch (final CAEntityNotInternalException ex) {
                logger.debug("Found external CA ", ex);
            }
        }

        return aPIModelList;
    }

    /**
     * Convert list of CertificateData entity objects to Certificate object model.
     *
     * @param certificateData
     *            CertificateData entity object
     * @return the Certificate api model object.
     *
     * @throws InvalidEntityAttributeException
     *             thrown when error occurred while getting certificateData due to invalid entity attribute.
     */
    public Certificate toObjectModel(final CertificateData certificateData) throws InvalidEntityAttributeException {
        final Certificate certificate = toCertificate(certificateData);
        if (certificateData.getIssuerCA() != null && certificateData.getIssuerCertificate() != null) {
            certificate.setIssuer(toCertAuthAPIModelWithoutIssuer(certificateData.getIssuerCA()));
            certificate.setIssuerCertificate(toObjectModel(certificateData.getIssuerCertificate()));
        }

        return certificate;
    }

    /**
     * Convert list of CertificateData entity objects to Certificate object model without chain.
     *
     * @param certificateData
     *            CertificateData entity object
     * @return the Certificate api model object.
     *
     * @throws InvalidEntityAttributeException
     *             thrown when error occurred while getting certificateData due to invalid entity attribute.
     */
    public Certificate toObjectModelWithOutChain(final CertificateData certificateData) throws InvalidEntityAttributeException {
        final Certificate certificate = toCertificate(certificateData);
        if (certificateData.getIssuerCA() != null && certificateData.getIssuerCertificate() != null) {
            certificate.setIssuer(toCertAuthAPIModelWithoutIssuer(certificateData.getIssuerCA()));
            certificate.setIssuerCertificate(toCertificateWithoutChain(certificateData.getIssuerCertificate()));
        }

        return certificate;
    }

    protected CAEntityData getIssuer(final CertificateAuthority issuer) throws EntityServiceException {
        CAEntityData caEntityData = null;
        if (!ValidationUtils.isNullOrEmpty(issuer.getName())) {
            try {
                caEntityData = persistenceManager.findEntityByName(CAEntityData.class, issuer.getName(), CA_NAME_PATH);
            } catch (final PersistenceException persistenceException) {
                throw new EntityServiceException("Issuer Not Found ", persistenceException);
            }
        }

        return caEntityData;
    }

    protected Subject toSubject(final String subjectString) {
        if (!ValidationUtils.isNullOrEmpty(subjectString)) {
            return new Subject().fromASN1String(subjectString);
        }

        return null;
    }

    protected String fromSubject(final Subject subject) {
        if (subject != null) {
            return subject.toASN1String();
        }

        return null;
    }

    protected SubjectAltName toSubjectAltName(final String subjectAltNameString) {
        if (!ValidationUtils.isNullOrEmpty(subjectAltNameString)) {
            return JsonUtil.getObjectFromJson(SubjectAltName.class, subjectAltNameString);
        }

        return null;
    }

    protected String fromSubjectAltName(final SubjectAltName subjectAltName) {
        if (subjectAltName != null) {
            return JsonUtil.getJsonFromObject(subjectAltName);
        }

        return null;
    }

    /**
     * Method to convert CAEntityData to CAEntity.
     *
     * @param caEntityData
     *            The caEntityData to convert.
     * @return CAEntity object.
     */
    public CAEntity issuerToAPIFromModel(final CAEntityData caEntityData) {

        final CAEntity caEntity = new CAEntity();

        caEntity.setCertificateAuthority(toCertAuthAPIModelWithoutIssuer(caEntityData));
        caEntity.setPublishCertificatetoTDPS(caEntityData.isPublishCertificatetoTDPS());

        if (caEntityData.getKeyGenerationAlgorithm() != null) {
            caEntity.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(caEntityData.getKeyGenerationAlgorithm()));
        }

        logger.debug("Mapped CAEntity domain model is {}", caEntity);

        return caEntity;
    }

    /**
     * Method to convert CAEntityData to CertificateAuthority. Only required fields of CertificateAuthority are set.
     *
     * @param caEntityData
     *            The caEntityData to convert.
     * @return CertificateAuthority object.
     */
    public CertificateAuthority toCertAuthAPIModelWithoutIssuer(final CAEntityData caEntityData) {

        if (caEntityData == null) {
            return null;
        }

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();

        certificateAuthority.setId(caEntityData.getId());
        certificateAuthority.setName(certificateAuthorityData.getName());
        certificateAuthority.setSubject(toSubject(certificateAuthorityData.getSubjectDN()));
        certificateAuthority.setSubjectAltName(toSubjectAltName(certificateAuthorityData.getSubjectAltName()));
        certificateAuthority.setRootCA(certificateAuthorityData.isRootCA());
        certificateAuthority.setStatus(CAStatus.getStatus(certificateAuthorityData.getStatus()));
        certificateAuthority.setPublishToCDPS(certificateAuthorityData.isPublishToCDPS());
        certificateAuthority.setIssuerExternalCA(certificateAuthorityData.isIssuerExternalCA());
        try {
            certificateAuthority.setCrlGenerationInfo(cRLGenerationInfoMapper.toAPIFromModel(certificateAuthorityData.getCrlGenerationInfo()));
        } catch (InvalidCRLGenerationInfoException | CertificateException | IOException e) {
            logger.error(ErrorMessages.INVALID_CRL_GENERATION_INFO_FOR_CA + certificateAuthorityData.getName());
            logger.debug(ErrorMessages.INVALID_CRL_GENERATION_INFO_FOR_CA + certificateAuthorityData.getName(), e);
        }

        return certificateAuthority;
    }

    private Certificate toCertificateWithoutChain(final CertificateData certificateData) throws InvalidEntityAttributeException {

        final Certificate certificate = toCertificate(certificateData);
        if (certificateData.getIssuerCA() != null && certificateData.getIssuerCertificate() != null) {
            certificate.setIssuer(toCertAuthAPIModelWithoutIssuer(certificateData.getIssuerCA()));
        }

        return certificate;
    }

    private Certificate toCertificate(final CertificateData certificateData) throws InvalidEntityAttributeException {
        final Certificate certificate = new Certificate();
        certificate.setId(certificateData.getId());
        certificate.setSerialNumber(certificateData.getSerialNumber());
        certificate.setNotBefore(certificateData.getNotBefore());
        certificate.setNotAfter(certificateData.getNotAfter());
        certificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));
        certificate.setIssuedTime(certificateData.getIssuedTime());
        certificate.setSubject(toSubject(certificateData.getSubjectDN()));
        X509Certificate x509Certificate = null;
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            x509Certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certificateData.getCertificate()));
            certificate.setX509Certificate(x509Certificate);
        } catch (CertificateException | NoSuchProviderException e) {
            throw new InvalidEntityAttributeException(ErrorMessages.INTERNAL_ERROR + e.getMessage(), e);
        }

        return certificate;
    }
}
