/*------------------------------------------------------------------------------
 *******************************************************************************
\ * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.override;

import java.util.Iterator;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;

/**
 * Class for handling overriding scenarios.
 * 
 * <p>
 * Overriding scenarios applicable for Subject and SubjectAltName fields.
 * </p>
 * 
 */
// TODO Improve the handling of validations and overriding Scenarios, this will be addressed as part of TORF-59437
public class SubjectOverrider {

    @Inject
    public Logger logger;

    /**
     * Method for overriding subject based on request.
     * 
     * @param entitySubject
     *            The entity subject.
     * @param certificateRequest
     *            The CertificateRequest Object.
     * @return the subject containing the overridden values.
     */
    public Subject overrideSubject(Subject entitySubject, final CertificateRequest certificateRequest) {

        logger.debug("Entity subject {} ", entitySubject);

        X500Name certificateRequestSubject = null;

        if (certificateRequest.getCertificateRequestHolder() != null) {

            if (certificateRequest.getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {
                final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = (PKCS10CertificationRequestHolder) certificateRequest.getCertificateRequestHolder();
                final PKCS10CertificationRequest pkcs10CertificationRequest = pkcs10CertificationRequestHolder.getCertificateRequest();
                certificateRequestSubject = pkcs10CertificationRequest.getSubject();
            } else {
                final CRMFRequestHolder crmfRequestHolder = (CRMFRequestHolder) certificateRequest.getCertificateRequestHolder();
                final CertificateRequestMessage crmfCertificationRequest = crmfRequestHolder.getCertificateRequest();
                certificateRequestSubject = crmfCertificationRequest.getCertTemplate().getSubject();
            }

        }
        entitySubject = checkForSubject(entitySubject, certificateRequestSubject);
        return entitySubject;
    }

    /**
     * Method for overriding entity subject fields values with CertificateRequest subject fields values. If entity subject field value has place holder then replace with CertificateRequest subject
     * field value.
     * 
     * @param entitySubject
     *            The entity subject.
     * @param certificateRequestSubject
     *            The certificate request subject.
     * @return the subject containing the overridden values.
     */
    public Subject checkForSubject(final Subject entitySubject, final X500Name certificateRequestSubject) throws InvalidSubjectException{

        logger.debug("Entity subject {} ", entitySubject);

        if (certificateRequestSubject != null && certificateRequestSubject.getRDNs().length > 0) {
            logger.info("Subject from CSR :::: {}", certificateRequestSubject);

            final Subject certificationRequestSubject = new Subject().fromASN1String(certificateRequestSubject.toString());
            final List<SubjectField> certificationRequestSubjectFields = certificationRequestSubject.getSubjectFields();
            final List<SubjectField> entitySubjectFields = entitySubject.getSubjectFields();

            for (final Iterator<SubjectField> iterator = entitySubjectFields.iterator(); iterator.hasNext();) {
                final SubjectField subjectField = iterator.next();
                if (subjectField.getValue().equals(Constants.OVERRIDE_OPERATOR)) {
                    if (verifyCertificateRequestFieldValue(certificationRequestSubjectFields, subjectField.getType())) {
                        final String subjectFieldValue = getCertificateRequestFieldValue(certificationRequestSubjectFields, subjectField.getType());

                        if (Constants.COMMA_SUPPORTED_DN_FIELD_TYPES.contains(subjectField.getType().getValue())
                                && subjectFieldValue != null && subjectFieldValue.matches(Constants.UNSUPPORTED_DIRECTORY_STRING_REGEX)) {
                            logger.info("Subject field value in CSR {} contains unsupported character (=/\"\\)",subjectFieldValue);
                            throw new InvalidSubjectException(ErrorMessages.UNSUPPORTED_CHARACTERS_FOR_CSR_DIRECTORY_STRING_SUBJECT);
                        }
                        else if (!Constants.COMMA_SUPPORTED_DN_FIELD_TYPES.contains(subjectField.getType().getValue()) && subjectFieldValue != null && subjectFieldValue.matches(Constants.UNSUPPORTED_CHAR_REGEX)) {
                            logger.info("Subject field value in CSR {} contains unsupported character (=/,\"\\)",subjectFieldValue);
                            throw new InvalidSubjectException(ErrorMessages.UNSUPPORTED_CHARACTERS_CSR_SUBJECT);
                        }
                        subjectField.setValue(subjectFieldValue);
                    } else {
                        iterator.remove();
                    }

                }

            }

        } else {
            removeOverrideOPeratorFromEntity(entitySubject.getSubjectFields());
        }

        return entitySubject;
    }

    private void removeOverrideOPeratorFromEntity(final List<SubjectField> subjectFields) {

        final Iterator<SubjectField> iterator = subjectFields.iterator();
        while (iterator.hasNext()) {
            final SubjectField subjectField = iterator.next();
            if (subjectField.getValue().equals(Constants.OVERRIDE_OPERATOR)) {
                iterator.remove();
            }

        }
    }

    private boolean verifyCertificateRequestFieldValue(final List<SubjectField> certificationRequestSubjectFields, final SubjectFieldType certificateRequestSubjectFieldType) {

        for (final SubjectField SubjectField : certificationRequestSubjectFields) {
            if (SubjectField.getType() == certificateRequestSubjectFieldType) {
                return true;
            }

        }
        return false;

    }

    private String getCertificateRequestFieldValue(final List<SubjectField> certificationRequestSubjectFields, final SubjectFieldType certificateRequestSubjectFieldType) {
        for (final SubjectField SubjectField : certificationRequestSubjectFields) {
            if (SubjectField.getType() == certificateRequestSubjectFieldType) {
                return SubjectField.getValue();
            }
        }
        return null;

    }

}
