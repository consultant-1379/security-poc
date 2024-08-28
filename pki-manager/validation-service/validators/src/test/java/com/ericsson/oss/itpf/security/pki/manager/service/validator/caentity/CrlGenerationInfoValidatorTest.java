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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.caentity;

import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameString;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.SignatureAlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CrlGenerationInfoSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.CRLExtensionsValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class CrlGenerationInfoValidatorTest {
    @Spy
    final Logger logger = LoggerFactory.getLogger(CrlGenerationInfoValidatorTest.class);

    @InjectMocks
    CrlGenerationInfoValidator crlGenerationInfoValidator;

    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesPersistenceHandler entitiesPersistenceHandler;
    @Mock
    SubjectValidator subjectValidator;

    @Mock
    SubjectAltNameValidator subjectAltNameValidator;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CRLExtensionsValidator crlExtensionsValidator;

    @Mock
    SignatureAlgorithmValidator signatureAlgorithmValidator;

    CAEntity caEntity;

    CAEntityData caEntityData;

    EntityProfileData entityProfileData;

    SubjectAltName subjectAltName = new SubjectAltName();
    List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
    SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
    SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
    Map<String, Object> entityProfileMap = new HashMap<String, Object>();
    Map<String, Object> keyGenAlgorithmMap = new HashMap<String, Object>();
    List<CrlGenerationInfo> crlGenerationInfoList = new ArrayList<CrlGenerationInfo>();

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        final CrlGenerationInfoSetUpData crlGenerationInfoSetUpData = new CrlGenerationInfoSetUpData();

        caEntity = entitiesSetUpData.getCaEntity();

        caEntityData = entitiesSetUpData.getCaEntityData();

        entityProfileData = caEntityData.getEntityProfileData();

        entityProfileMap.put("name", "ENMRootCAEntityProfile");
        entityProfileMap.put("active", Boolean.TRUE);

        keyGenAlgorithmMap.put(EntitiesSetUpData.NAME, "RSA");
        keyGenAlgorithmMap.put(EntitiesSetUpData.ALGORITHM_KEY_SIZE, 1024);
        keyGenAlgorithmMap.put(EntitiesSetUpData.ALGORITHM_TYPE, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY)).thenReturn(entitiesPersistenceHandler);

        when(entitiesPersistenceHandler.getEntityByName(entityProfileData.getName(), EntityProfileData.class, "name")).thenReturn(entityProfileData);

        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);

        crlGenerationInfoList.add(crlGenerationInfoSetUpData.getCrlGenerationInfo());

    }

    /**
     * Method to test validate method in negative scenario. When CrlGenerationInfo version is set to null .
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testVersionNull() {
        caEntity.getCertificateAuthority().setName("ENMSubCA");

        when(entitiesPersistenceHandler.getEntityById(1, CAEntityData.class)).thenReturn(null);
        for (final CrlGenerationInfo crlGenerationInfo : crlGenerationInfoList) {
            crlGenerationInfo.setVersion(null);
        }
        caEntity.getCertificateAuthority().setCrlGenerationInfo(crlGenerationInfoList);

        crlGenerationInfoValidator.validate(caEntity);
    }

    /**
     * Method to test validate with EmptyCrlList.
     */
    @Test
    public void testWithEmptyCrlList() {
        caEntity.getCertificateAuthority().setName("ENMSubCA");

        when(entitiesPersistenceHandler.getEntityById(1, CAEntityData.class)).thenReturn(null);

        caEntity.getCertificateAuthority().setCrlGenerationInfo(new ArrayList<CrlGenerationInfo>());

        crlGenerationInfoValidator.validate(caEntity);
    }

    @Test
    public void testValidateCrlGenerationInfo() {

        caEntity.getCertificateAuthority().setName("ENMSubCA");
        when(entitiesPersistenceHandler.getEntityById(1, CAEntityData.class)).thenReturn(null);
        caEntity.getCertificateAuthority().setCrlGenerationInfo(crlGenerationInfoList);
        crlGenerationInfoValidator.validate(caEntity);

    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidatyPeriodNull() {

        for (final CrlGenerationInfo crlGenerationInfo : crlGenerationInfoList) {
            crlGenerationInfo.setValidityPeriod(null);
        }
        caEntity.getCertificateAuthority().setCrlGenerationInfo(crlGenerationInfoList);
        crlGenerationInfoValidator.validate(caEntity);
        Mockito.verify(logger).debug("Validating CrlGenerationInfo for CA Entity {}", caEntity.getCertificateAuthority().getName());

    }

    @Test(expected = InvalidCRLGenerationInfoException.class)
    public void testValidateDurationFormat() throws DatatypeConfigurationException {

        for (final CrlGenerationInfo crlGenerationInfo : crlGenerationInfoList) {
            crlGenerationInfo.setSkewCrlTime(DatatypeFactory.newInstance().newDuration(1l));
        }

        caEntity.getCertificateAuthority().setCrlGenerationInfo(crlGenerationInfoList);
        crlGenerationInfoValidator.validate(caEntity);

    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testSignatureAlgorithm_InValidAlgorithm() {

        for (final CrlGenerationInfo crlGenerationInfo : crlGenerationInfoList) {
            crlGenerationInfo.setSignatureAlgorithm(null);
        }
        caEntity.getCertificateAuthority().setCrlGenerationInfo(crlGenerationInfoList);
        crlGenerationInfoValidator.validate(caEntity);
    }
}
