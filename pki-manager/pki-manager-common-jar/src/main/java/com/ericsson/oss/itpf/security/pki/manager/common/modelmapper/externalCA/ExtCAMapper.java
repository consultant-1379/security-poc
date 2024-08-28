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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA;

import java.util.*;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;

import org.bouncycastle.asn1.x500.*;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;

@RequestScoped
public class ExtCAMapper extends CAEntityMapper {

    @Inject
    ExternalCRLMapper crlMapper;

    /**
     * Maps the CA Entity JPA model to its corresponding API model
     *
     * @param entityData
     *            CAEntityData Object which should be converted to API model CAEntity
     *
     * @throws ExternalCRLEncodedException
     *             Thrown when the CRL is not correct.
     *
     * @return Returns the API model of the given JPA model
     *
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T, E> T toAPIFromModel(final E entityData) throws ExternalCRLEncodedException {

        final CAEntityData caEntityData = (CAEntityData) entityData;

        logger.debug("Mapping CAEntityData entity {} to CAEntity domain model.", caEntityData.getId());
        final CertificateAuthority certificateAuthority = externalCAtoAPIFromModelCertAuth(caEntityData);

        final ExtCA extCA = new ExtCA();
        extCA.setCertificateAuthority(certificateAuthority);

        if (caEntityData.getCertificateAuthorityData().getExternalCrlInfoData() != null) {
            extCA.setExternalCRLInfo(crlMapper.toAPIFromModel(caEntityData.getCertificateAuthorityData().getExternalCrlInfoData()));
        }

        final Set<CAEntityData> associated = caEntityData.getAssociated();
        if (!associated.isEmpty()) {
            final List<ExtCA> listExtCA = toAPIFromModelAssociated(associated);
            extCA.setAssociated(listExtCA);
        }

        return (T) extCA;
    }

    private CertificateAuthority externalCAtoAPIFromModelCertAuth(final CAEntityData caEntityData) {
        if (caEntityData == null) {
            return null;
        }

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        final CertificateAuthorityData certificateAuthorityData = caEntityData.getCertificateAuthorityData();

        final CertificateAuthority issuerCertificateAuthority = new CertificateAuthority();
        final CAEntityData issuerCAEntityData = caEntityData.getCertificateAuthorityData().getIssuer();

        if (issuerCAEntityData != null) {
            issuerCertificateAuthority.setId(issuerCAEntityData.getId());
            issuerCertificateAuthority.setName(issuerCAEntityData.getCertificateAuthorityData().getName());
        }

        certificateAuthority.setId(caEntityData.getId());
        certificateAuthority.setName(certificateAuthorityData.getName());
        if (validateSubjectForAPI(certificateAuthorityData.getSubjectDN())) {
            certificateAuthority.setSubject(toSubject(certificateAuthorityData.getSubjectDN()));
        }
        certificateAuthority.setSubjectAltName(toSubjectAltName(certificateAuthorityData.getSubjectAltName()));
        certificateAuthority.setRootCA(certificateAuthorityData.isRootCA());
        certificateAuthority.setStatus(CAStatus.getStatus(certificateAuthorityData.getStatus()));
        certificateAuthority.setPublishToCDPS(certificateAuthorityData.isPublishToCDPS());
        certificateAuthority.setIssuer(issuerCertificateAuthority);

        return certificateAuthority;
    }

    /**
     * @param subjectDN
     * @return
     */
    private boolean validateSubjectForAPI(final String subjectDN) {
        final X500Name x500Name = new X500Name(subjectDN);
        for (final RDN rdn : x500Name.getRDNs()) {
            for (final AttributeTypeAndValue attributeTypeAndValue : rdn.getTypesAndValues()) {
                boolean found = false;
                for (final SubjectFieldType subjectFieldType : SubjectFieldType.values()) {
                    if (subjectFieldType.getOID().equals(attributeTypeAndValue.getType().toString())) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @param associated
     */
    private List<ExtCA> toAPIFromModelAssociated(final Set<CAEntityData> associated) throws ExternalCRLEncodedException {
        final List<ExtCA> listExtCA = new ArrayList<ExtCA>();
        for (final CAEntityData entityData : associated) {
            final ExtCA extSubCA = toAPIFromModel(entityData);
            listExtCA.add(extSubCA);
        }
        return listExtCA;
    }

    /**
     * Maps the CA Entity API model to its corresponding JPA model
     *
     * @param entityData
     *            CAEntity Object which should be converted to JPA model CAEntityData
     *
     * @return Returns the JPA model of the given API model
     *
     * @throws CRLServiceException
     *             thrown when any internal Database errors occur.
     * @ExternalCRLEncodedException
     *
     */
    @SuppressWarnings("unchecked")
    @Override
    public <T, E> E fromAPIToModel(final T APIModel) throws CRLServiceException, ExternalCRLEncodedException {
        final CAEntityData caEntityData = new CAEntityData();
        final ExtCA extCA = (ExtCA) APIModel;
        final CertificateAuthority certificateAuthority = extCA.getCertificateAuthority();

        caEntityData.setId(certificateAuthority.getId());
        final CertificateAuthorityData certificateAuthorityData = fromAPIToModelCertAuth(certificateAuthority);
        if (extCA.getExternalCRLInfo() != null) {
            certificateAuthorityData.setExternalCrlInfoData(crlMapper.fromAPIToModel(extCA.getExternalCRLInfo()));
        }
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.setExternalCA(true);

        caEntityData.setAssociated(fromAPIToModelAssociated(extCA.getAssociated()));
        logger.debug("Mapped CAEntityData entity is {}", caEntityData);

        return (E) caEntityData;
    }

    /**
     * @param associated
     */
    private Set<CAEntityData> fromAPIToModelAssociated(final List<ExtCA> extCAs) throws CRLServiceException {
        final Set<CAEntityData> caEntityDatas = new HashSet<CAEntityData>();
        for (final ExtCA extCA : extCAs) {
            final CAEntityData entityData = new CAEntityData();
            entityData.setCertificateAuthorityData(fromAPIToModelCertAuth(extCA.getCertificateAuthority()));
            caEntityDatas.add(entityData);
        }
        return caEntityDatas;
    }

}
