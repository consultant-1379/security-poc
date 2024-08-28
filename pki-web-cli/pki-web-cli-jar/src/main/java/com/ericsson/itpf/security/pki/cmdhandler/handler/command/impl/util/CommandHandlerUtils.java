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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.*;
import java.text.*;
import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;
import com.ericsson.oss.itpf.sdkutils.exception.CommonRuntimeException;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.utils.XSDValidator;

/**
 * Common Utility for various operations like fetching profile(s) or entitie(s) object from user input xml file in case of import/create/update etc
 * <p>
 * Validating String pattern like entered Profile Name pattern, DNS Name etc..
 * </p>
 *
 */
public class CommandHandlerUtils {
    @Inject
    public CliUtil cliutil;

    @Inject
    Logger logger;

    /**
     * Method to fetch the profiles from input xml file given by user
     *
     *
     * @param pkiPropertyCommand
     * @return
     * @throws CommonRuntimeException
     */
    public Profiles getProfilesFromInputXml(final PkiPropertyCommand pkiPropertyCommand) throws CommonRuntimeException {

        InputStream inputStream = null;
        final Profiles profiles;
        final String xmlFileContent;

        try {
            xmlFileContent = cliutil.getFileContentFromCommandProperties(pkiPropertyCommand.getProperties());

            inputStream = new ByteArrayInputStream(xmlFileContent.getBytes());
            profiles = XSDValidator.profilesValidator(inputStream);
        } catch (final Exception exception) {
            logger.error("Error while reading the input file: {}", exception.getMessage());
            throw new CommonRuntimeException("Error while reading the input file " + exception.getMessage());
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (final IOException exception) {
                logger.error("Error while closing the inputstream: {}", exception.getMessage());
            }

        }

        return profiles;
    }

    /**
     * Method to fetch the profiles from input xml file given by user from webcli for updating profile
     * @param pkiPropertyCommand
     * @return Profiles
     * @throws IllegalArgumentException
     *
     *
     */
    public Profiles getUpdatedProfilesFromInputXml(final PkiPropertyCommand pkiPropertyCommand) throws IllegalArgumentException {

        InputStream inputStream = null;
        final Profiles profiles;
        final String xmlFileContent;

        try {
            xmlFileContent = cliutil.getFileContentFromCommandProperties(pkiPropertyCommand.getProperties());

            inputStream = new ByteArrayInputStream(xmlFileContent.getBytes());
            profiles = XSDValidator.profilesValidator(inputStream);
        } catch (final Exception exception) {
            logger.error("Error while reading the input file: {}", exception.getMessage());
            throw new IllegalArgumentException("Error while reading the input file " + exception.getMessage());
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (final IOException exception) {
                logger.error("Error while closing the inputstream: {}", exception.getMessage());
            }

        }

        return profiles;
    }

    /**
     * Method to fetch the entities from input xml file given by user from webcli
     * @param pkiPropertyCommand
     * @return Entities
     * @throws IllegalArgumentException
     *
     */
    public Entities getEntitiesFromInputXml(final PkiPropertyCommand pkiPropertyCommand) throws IllegalArgumentException {

        InputStream inputStream = null;
        final Entities entities;
        final String xmlFileContent;

        try {
            xmlFileContent = cliutil.getFileContentFromCommandProperties(pkiPropertyCommand.getProperties());

            inputStream = new ByteArrayInputStream(xmlFileContent.getBytes());
            entities = XSDValidator.entitiesValidator(inputStream);

        } catch (final Exception exception) {
            logger.error("Error while reading the input file: {}", exception.getMessage());
            throw new IllegalArgumentException("Error while reading the input file " + exception.getMessage());
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (final IOException exception) {
                logger.error("Error while closing the inputstream: {}", exception.getMessage());
            }

        }

        return entities;
    }

    /**
     * Method to fetch the entities from input xml file given by user from webcli
     * @param pkiPropertyCommand
     * @return Entities
     * @throws IllegalArgumentException
     *
     */
    public Entities getUpdatedEntitiesFromInputXml(final PkiPropertyCommand pkiPropertyCommand) throws IllegalArgumentException {

        InputStream inputStream = null;
        final Entities entities;
        final String xmlFileContent;

        try {
            xmlFileContent = cliutil.getFileContentFromCommandProperties(pkiPropertyCommand.getProperties());

            inputStream = new ByteArrayInputStream(xmlFileContent.getBytes());
            entities = XSDValidator.entitiesValidator(inputStream);

        } catch (final Exception exception) {
            logger.error("Error while reading the input file: {}", exception.getMessage());
            throw new IllegalArgumentException("Error while reading the input file " + exception.getMessage());
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (final IOException exception) {
                logger.error("Error while closing the inputstream: {}", exception.getMessage());
            }

        }

        return entities;
    }

    /**
     * Method for getting profile enum from a given string
     *
     * @param profileType
     * @return ProfileType
     * @throws IllegalArgumentException
     */
    public ProfileType getProfileType(final String profileType) throws IllegalArgumentException {
        ProfileType profile = null;

        switch (profileType) {
        case Constants.CERTIFICATE:
            profile = ProfileType.CERTIFICATE_PROFILE;
            break;
        case Constants.ENTITY:
            profile = ProfileType.ENTITY_PROFILE;
            break;
        case Constants.TRUST:
            profile = ProfileType.TRUST_PROFILE;
            break;
        default:
            throw new IllegalArgumentException("Unsupported profiletype " + profileType);
        }

        return profile;
    }

    /**
     * Method for getting entity enum from a given string
     *
     * @param entityType
     * @return EntityType
     * @throws IllegalArgumentException
     */
    public EntityType getEntityType(final String entityType) throws IllegalArgumentException {
        EntityType entity = null;
        switch (entityType) {
        case Constants.CA:
            entity = EntityType.CA_ENTITY;
            break;
        case Constants.EE:
            entity = EntityType.ENTITY;
            break;
        default:
            throw new IllegalArgumentException("Unsupported entitytype " + entityType);
        }

        return entity;
    }

    /**
     * Method for getting profile instance from a given profile type(enum)
     *
     * @param profileType
     * @return AbstractProfile
     * @throws IllegalArgumentException
     */
    public AbstractProfile getProfileInstance(final ProfileType profileType) throws IllegalArgumentException {
        AbstractProfile profile = null;

        switch (profileType) {
        case CERTIFICATE_PROFILE:
            profile = new CertificateProfile();
            break;
        case ENTITY_PROFILE:
            profile = new EntityProfile();
            break;
        case TRUST_PROFILE:
            profile = new TrustProfile();
            break;
        default:
            logger.error("There is no object present with profile Type");
            throw new IllegalArgumentException(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR);
        }

        return profile;
    }

    /**
     * Method for getting entity instance from a given entity type(enum) and name
     * @param entityType
     * @param entityName
     * @return AbstractEntity
     * @throws IllegalArgumentException
     */
    @SuppressWarnings("unchecked")
    public <T extends AbstractEntity> T getEntityInstance(final EntityType entityType, final String entityName) throws IllegalArgumentException {
        T abstractEntity = null;

        switch (entityType) {
        case CA_ENTITY:
            final CAEntity caEntity = new CAEntity();
            final CertificateAuthority certificateAuthority = new CertificateAuthority();
            certificateAuthority.setName(entityName);
            caEntity.setCertificateAuthority(certificateAuthority);
            abstractEntity = (T) caEntity;
            break;
        case ENTITY:
            final Entity entity = new Entity();
            final EntityInfo entityInfo = new EntityInfo();
            entityInfo.setName(entityName);
            entity.setEntityInfo(entityInfo);
            abstractEntity = (T) entity;
            break;
        default:
            logger.error("There is no object present with entity Type all");
            throw new IllegalArgumentException(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR);
        }

        return abstractEntity;
    }

    /**
     * Method for getting profiles object from a list of profiles
     *
     * @param profileType
     * @param listOfProfiles
     * @return Profiles
     * @throws IllegalArgumentException
     */
    public <T> Profiles setProfiles(final ProfileType profileType, final List<T> listOfProfiles) throws IllegalArgumentException {
        final Profiles profiles = new Profiles();

        switch (profileType) {
        case CERTIFICATE_PROFILE: {
            profiles.setCertificateProfiles(castList(CertificateProfile.class, listOfProfiles));
            break;
        }
        case ENTITY_PROFILE: {
            profiles.setEntityProfiles(castList(EntityProfile.class, listOfProfiles));
            break;
        }
        case TRUST_PROFILE: {
            profiles.setTrustProfiles(castList(TrustProfile.class, listOfProfiles));
            break;
        }
        default:
            logger.error("There is no object present with profile Type");
            throw new IllegalArgumentException(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR);
        }

        return profiles;
    }

    /**
     * Method for getting entities object from a list of entities
     *
     * @param entityType
     * @param listOfEntities
     * @return Entities
     * @throws IllegalArgumentException
     */
    public <T> Entities setEntities(final EntityType entityType, final List<T> listOfEntities) throws IllegalArgumentException {
        final Entities entities = new Entities();

        switch (entityType) {
        case CA_ENTITY: {
            entities.setCAEntities(castList(CAEntity.class, listOfEntities));
            break;
        }
        case ENTITY: {
            entities.setEntities(castList(Entity.class, listOfEntities));
            break;
        }
        default:
            logger.error("There is no object present with profile Type");
            throw new IllegalArgumentException(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR);
        }

        return entities;
    }

    /**
     * Method for fetching list of profiles of a specific type from profiles object
     * @param profiles
     * @param profileType
     * @return List of Profiles
     * @throws IllegalArgumentException
     */
    public List<? extends AbstractProfile> getProfileByType(final Profiles profiles, final ProfileType profileType) throws IllegalArgumentException {
        List<? extends AbstractProfile> abstractProfile;

        switch (profileType) {
        case CERTIFICATE_PROFILE:
            abstractProfile = profiles.getCertificateProfiles();
            break;
        case ENTITY_PROFILE:
            abstractProfile = profiles.getEntityProfiles();
            break;
        case TRUST_PROFILE:
            abstractProfile = profiles.getTrustProfiles();
            break;
        default:
            throw new IllegalArgumentException("unsupported profiletype " + profileType);
        }

        return abstractProfile;
    }

    /**
     * Method for getting list of profiles from a collection of profile
     *
     * @param listOfProfiles
     * @return List of Profiles
     */
    @SuppressWarnings("unchecked")
    public List<AbstractProfile> getAllProfiles(final Collection<? extends AbstractProfile>... listOfProfiles) {
        final ArrayList<AbstractProfile> abstractProfiles = new ArrayList<>();

        for (final Collection<? extends AbstractProfile> profiles : listOfProfiles) {
            if (profiles != null) {
                abstractProfiles.addAll(profiles);
            }
        }

        return abstractProfiles;
    }

    /**
     * Method for getting list of entities from a collection of entities
     *
     * @param listOfEntities
     * @return List of Entities
     */
    @SuppressWarnings("unchecked")
    public List<AbstractEntity> getAllEntries(final Collection<? extends AbstractEntity>... listOfEntities) {
        final ArrayList<AbstractEntity> abstractEntities = new ArrayList<>();

        for (final Collection<? extends AbstractEntity> entities : listOfEntities) {
            if (entities != null) {
                abstractEntities.addAll(entities);
            }
        }

        return abstractEntities;
    }

    /**
     * Method for casting objects of a collection to a specific type
     *
     * @param toCastClass
     * @param collection
     * @return List
     */
    public <T> List<T> castList(final Class<? extends T> toCastClass, final Collection<?> collection) {
        final List<T> castedList = new ArrayList<T>(collection.size());

        for (final Object object : collection) {
            castedList.add(toCastClass.cast(object));
        }

        return castedList;
    }

    /**
     * Method for getting the certificate from input file.
     *
     * @param pkiPropertyCommand
     * @return X509Certificate
     * @throws CertificateException
     * @throws IllegalArgumentException
     * @throws CertificateNotFoundException
     */
    public X509Certificate getCertificateFromInputFile(final PkiPropertyCommand pkiPropertyCommand) throws CertificateException, IllegalArgumentException, CertificateNotFoundException {
        X509Certificate certificate = null;
        final String filePath = (String) pkiPropertyCommand.getProperties().get("filePath");

        if (filePath != null && !filePath.isEmpty()) {
            final String osAppropriatePath = Constants.FILE_SEPARATOR.equalsIgnoreCase("/") ? filePath : filePath.substring(1);
            final Base64Reader br = new Base64Reader("", osAppropriatePath, "", "", "");

            final Certificate pemCertificate = br.getCertificate("");
            if (pemCertificate == null) {
                throw new IllegalArgumentException(PkiErrorCodes.NO_CERTIFICATE_FOUND);
            }
            CertificateFactory certFactory;
            try {
                certFactory = CertificateFactory.getInstance("X.509");
                final InputStream inputStream = new ByteArrayInputStream(pemCertificate.getEncoded());
                certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
            } catch (java.security.cert.CertificateException e) {
                throw new CertificateException(e.getMessage());
            }
        }

        return certificate;
    }

    /**
     * Method to get the CRL from the input file.
     *
     * @param pkiPropertyCommand
     * @return X509CRL
     * @throws CRLException
     * @throws IOException
     */
    public X509CRL getCRLFromInputFile(final PkiPropertyCommand pkiPropertyCommand) throws CRLException, IOException {

        final String filePath = (String) pkiPropertyCommand.getProperties().get("filePath");

        X509CRL x509CRL = null;
        if (filePath != null && !filePath.isEmpty()) {
            final String osAppropriatePath = Constants.FILE_SEPARATOR.equalsIgnoreCase("/") ? filePath : filePath.substring(1);
            try(InputStream crlFile = new FileInputStream(osAppropriatePath);) {
                final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                x509CRL = (X509CRL) certificateFactory.generateCRL(crlFile);
            } catch (FileNotFoundException | java.security.cert.CertificateException e) {
                throw new CRLException(e.getMessage());
            }
        }

        return x509CRL;
    }

    /**
     * @param pkiPropertyCommand
     * @return X509CRL
     * @throws CRLException
     */
    public X509CRL getCRLFromURL(final PkiPropertyCommand pkiPropertyCommand) throws CRLException {

        InputStream crlFile = null;
        final String fileURL = (String) pkiPropertyCommand.getProperties().get("url");

        X509CRL x509CRL = null;
        URL url;
        try {
            url = new URL(fileURL);

            final HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
            httpConn.setRequestMethod("GET");
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);

            final int responseCode = httpConn.getResponseCode();

            // always check HTTP response code first
            if (responseCode == HttpURLConnection.HTTP_OK) {
                crlFile = httpConn.getInputStream();
                if (crlFile != null) {
                    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    x509CRL = (X509CRL) certificateFactory.generateCRL(crlFile);
                }
            }
        } catch (IOException | java.security.cert.CertificateException e) {
            throw new CRLException(e.getMessage());
        }
        return x509CRL;
    }

    /**
     * Method for fetching the revocation reason from the webcli command given by the user.

     * @param command
     * @return RevocationReason
     * @throws CommonRuntimeException
     *             if the reason code from the command is not proper or not from specified values of that.
     *
     * @throws IllegalArgumentException
     *             if the revocation reason Code and Text from command is not from the specified values of revocation reason.
     */
    public RevocationReason getRevocationReason(final PkiPropertyCommand command) throws CommonRuntimeException, IllegalArgumentException {
        PkiRevocationReasonType pkiRevocationReasonType = null;
        final RevocationReason revocationReason;

        if (command.hasProperty(Constants.REVOCATION_REASON_TEXT)) {
            pkiRevocationReasonType = PkiRevocationReasonType.fromReasonText(command.getValueString(Constants.REVOCATION_REASON_TEXT));
        } else if (command.hasProperty(Constants.REVOCATION_REASON_CODE)) {
            pkiRevocationReasonType = PkiRevocationReasonType.fromReasonCode(command.getValueString(Constants.REVOCATION_REASON_CODE));
        } else {
            throw new IllegalArgumentException("Invalid revocation reason type");
        }
        try {
            final int reasonCode = Integer.parseInt(pkiRevocationReasonType.getReasonCode());
            revocationReason = RevocationReason.getNameByValue(reasonCode);

        } catch (NumberFormatException numberFormatException) {
            logger.error("Error while parsing the String Object into Date object: {}", numberFormatException.getMessage());
            throw new CommonRuntimeException(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR);
        }
        return revocationReason;

    }

    /**
     * Method for fetching the invalidity Date from the value taken from webcli command given by the user.
     * @param invalidityDateValue
     *            Is an input date in yyyy-MM-dd HH:mm:ss format.
     * @return Date
     *  @throws CommonRuntimeException
     *             If the reason code from the command is not proper or not from specified values of that.
     *
     */
    public Date getInvalidityDateInGmt(final String invalidityDateValue) throws CommonRuntimeException {

        Date invalidityDate = null;
        final String format = "yyyy-MM-dd HH:mm:ss";
        try {
            final DateFormat df = new SimpleDateFormat(format);
            invalidityDate = df.parse(invalidityDateValue);

        } catch (ParseException parseException) {
            logger.error("Error while parsing the String Object into Date object: {}", parseException.getMessage());
            throw new CommonRuntimeException(PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR);
        }
        return invalidityDate;

    }

    /**
     * Method for converting the date to yyyy-MM-dd HH:mm:ss format
     *
     * @param date
     * @return String
     *
     *
     */
    public String getDateString(final Date date) {

        String profileValidity = Constants.EMPTY_STRING;
        try {
            final SimpleDateFormat sdf = new SimpleDateFormat(Constants.DATE_FORMAT);
            profileValidity = sdf.format(date);
        } catch (IllegalArgumentException illegalArgumentException) {
            logger.error("Error while checking the profile validity  pattern: {}", illegalArgumentException.getMessage());
        }
        return profileValidity;
    }

    /**
     * Method to add in utility case to append the Strings
     *
     * @param iterable
     * @param delimiter
     * @return String
     *
     */

    public static <E> String getFieldValues(final Iterable<E> iterable, final String delimiter) {
        final Iterator<E> iterator = iterable.iterator();
        if (!iterator.hasNext()) {
            return "";
        }
        final StringBuilder builder = new StringBuilder();
        builder.append(iterator.next());
        while (iterator.hasNext()) {
            builder.append(delimiter).append(iterator.next());
        }
        return builder.toString();
    }

    /**
     * Method to get all Subject Field Types and Values in String format separated by comma
     * @param subject
     * @return String
     */
    public String getAllSubjectFields(final Subject subject) {

        final List<String> subjectStrings = new ArrayList<>();
        final List<SubjectField> subjectFieldList = subject.getSubjectFields();

        if (ValidationUtils.isNullOrEmpty(subjectFieldList)) {
            return Constants.EMPTY_STRING;
        }
        for (final SubjectField subjectField : subjectFieldList) {
            final SubjectFieldType subjectFieldType = subjectField.getType();
            final String subjectFieldValue = subjectField.getValue();
            final String valueOfEachSubjectField = subjectFieldType.getName() + Constants.EQUALS + (null != subjectFieldValue ? subjectFieldValue : Constants.SPACE_STRING);
            subjectStrings.add(valueOfEachSubjectField);
        }
        return getFieldValues(subjectStrings, Constants.COMMA);
    }

    /**
     * Method to get all SubjectAltName Field Types and Values in String format separated by comma
     * @param subjectAltName
     * @return String
     */

    public String getAllSubjectAltNameFields(final SubjectAltName subjectAltName) {

        final List<String> subjectAltNameStringList = new ArrayList<>();
        final List<SubjectAltNameField> subjectAltNameFields = subjectAltName.getSubjectAltNameFields();

        if (ValidationUtils.isNullOrEmpty(subjectAltNameFields)) {
            return Constants.EMPTY_STRING;
        }

        for (final SubjectAltNameField subjectAltNameField : subjectAltNameFields) {
            final String subjectAltNameFieldValue = subjectAltNameField.getType().name() + Constants.EQUALS
                    + (null != subjectAltNameField.getValue() ? subjectAltNameField.getValue() : Constants.SPACE_STRING);

            subjectAltNameStringList.add(subjectAltNameFieldValue);
        }
        return getFieldValues(subjectAltNameStringList, Constants.COMMA);
    }

    /**
     * Method to get all KeyGenaration Algorithm Details in String format separated by comma
     * @param keyGenerationAlgorithms
     * @return String
     */
    public String getKeyGenerationAlgorithmDetails(final List<Algorithm> keyGenerationAlgorithms) {

        if (ValidationUtils.isNullOrEmpty(keyGenerationAlgorithms)) {
            return Constants.EMPTY_STRING;
        }

        final List<String> keyGenerationAlgorithmStrings = new ArrayList<>();
        for (final Algorithm keyGenerationAlgorithm : keyGenerationAlgorithms) {
            final String keyGenerationAlgorithmString = getKeyGenerationAlgorithmString(keyGenerationAlgorithm);
            keyGenerationAlgorithmStrings.add(keyGenerationAlgorithmString);
        }
        return getFieldValues(keyGenerationAlgorithmStrings, Constants.COMMA);
    }

    /**
     * Method to get KeyGenaration Algorithm Fields in String format
     *
     * @param keyGenerationAlgorithm
     * @return String
     */
    public String getKeyGenerationAlgorithmString(final Algorithm keyGenerationAlgorithm) {
        return  keyGenerationAlgorithm.getName() + Constants.HYPHEN + String.valueOf(keyGenerationAlgorithm.getKeySize()) + Constants.COMMA + Constants.TYPE
                + keyGenerationAlgorithm.getType();
    }

    /**
     *
     * Method for fetching the certificate status from the value taken from webcli command given by the user.
     *
     * @param status
     * @return CertificateStatus
     *
     * @throws IllegalArgumentException
     *
     */
    public CertificateStatus getCertificateStatus(final String status) throws IllegalArgumentException {

        CertificateStatus certificateStatus = null;

        switch (status) {
        case Constants.CERTIFICATE_ACTIVE_STATUS:
            certificateStatus = CertificateStatus.ACTIVE;
            break;
        case Constants.CERTIFICATE_REVOKED_STATUS:
            certificateStatus = CertificateStatus.REVOKED;
            break;

        case Constants.CERTIFICATE_EXPIRED_STATUS:
            certificateStatus = CertificateStatus.EXPIRED;
            break;

        case Constants.CERTIFICATE_INACTIVE_STATUS:
            certificateStatus = CertificateStatus.INACTIVE;
            break;
        default:
            throw new IllegalArgumentException(PkiErrorCodes.CERTIFICATE_STATUS_NOT_SUPPORTED);
        }
    return certificateStatus;
    }

}
