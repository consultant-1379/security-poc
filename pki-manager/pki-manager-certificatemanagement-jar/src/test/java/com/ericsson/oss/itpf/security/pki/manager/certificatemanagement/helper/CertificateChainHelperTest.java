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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.PersistenceException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.CertificateManagementBaseTest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.EntitySetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.EntityCertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

@RunWith(MockitoJUnitRunner.class)
public class CertificateChainHelperTest extends CertificateManagementBaseTest {

    @InjectMocks
    CertificateChainHelper certificateChainHelper;

    @Mock
    EntityCertificatePersistenceHelper entityPersistenceHelper;

    @Mock
    CACertificatePersistenceHelper caPersistenceHelper;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    EntityHelper entityHelper;

    @Mock
    Logger logger;

    private static SetUPData setUPData = new SetUPData();
    private static EntitySetUPData entitySetUPData = new EntitySetUPData();

    /**
     * Test Case for Retrieving Active certificate chain list For Entity.
     *
     * @throws Exception
     */
    @Test
    public void testGetCertificateChainList_Entity_CertificateStatus_Active() throws Exception {

        mockEntity(EntityType.ENTITY);
        mockEntityCertificate(CertificateStatus.ACTIVE);
        mockEntityCertificateChain(setUPData.getEntityCertificate(), CertificateStatus.ACTIVE);

        final List<CertificateChain> actualCertificateChains = certificateChainHelper.getCertificateChainList(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                CertificateStatus.ACTIVE);

        final List<CertificateChain> expectedCertificateChains = setUPData.getEntityCertificateChain(CertificateStatus.ACTIVE);

        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    /**
     * Test Case for Retrieving InActive certificate chain List For Entity.
     *
     * @throws Exception
     */
    @Test
    public void testGetCertificateChainList_Entity_CertificateStatus_InActive() throws Exception {

        mockEntity(EntityType.ENTITY);
        mockEntityCertificate(CertificateStatus.INACTIVE);

        final Certificate certificate = setUPData.getEntityCertificate();
        certificate.setStatus(CertificateStatus.INACTIVE);
        mockEntityCertificateChain(certificate, CertificateStatus.INACTIVE);

        final List<CertificateChain> actualCertificateChains = certificateChainHelper.getCertificateChainList(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                CertificateStatus.INACTIVE);

        final List<CertificateChain> expectedCertificateChains = setUPData.getEntityCertificateChain(CertificateStatus.INACTIVE);

        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    /**
     * Test Case for checking InvalidEntityException when the given entity doesn't have an active certificate.
     *
     * @throws Exception
     */
    @Test(expected = InvalidEntityException.class)
    public void testGetCertificateChainList_Entity_Active_Certificate_Not_Found() throws Exception {

        mockEntity(EntityType.ENTITY);
        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE)).thenReturn(null);
        certificateChainHelper.getCertificateChainList(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE);

    }

    /**
     * Test Case for checking InvalidEntityException when the given entity doesn't have inactive certificate.
     *
     * @throws Exception
     */
    @Test(expected = InvalidEntityException.class)
    public void testGetCertificateChainList_Entity_InActive_Certificate_Not_Found() throws Exception {

        mockEntity(EntityType.ENTITY);
        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_0, CertificateStatus.INACTIVE)).thenReturn(null);
        certificateChainHelper.getCertificateChainList(SetUPData.ENTITY_NAME, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.INACTIVE);

    }

    /**
     * Test Case for checking InvalidCAException is thrown when the issuer certificate of given entity doesn't have an active certificate and inactive certificate.
     *
     * @throws Exception
     */
    @Test(expected = InvalidCAException.class)
    public void testGetCertificateChain_Entity_Issuer_Certificate_Revoked() throws Exception {

        mockEntity(EntityType.ENTITY);
        mockEntityCertificate(CertificateStatus.ACTIVE);
        Mockito.when(certificatePersistenceHelper.getCertificateChain(setUPData.getEntityCertificate(), Constants.INACTIVE_CERTIFICATE_VALID)).thenThrow(
                new InvalidCAException(ErrorMessages.ISSUER_CERITICATE_IS_REVOKED_OR_EXPIRED));

        certificateChainHelper.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, CertificateStatus.ACTIVE);
    }

    /**
     * Test Case for checking CertificateServiceException is thrown when trying to get active certificate from DB.
     *
     * @throws Exception
     */
    @Test(expected = CertificateServiceException.class)
    public void testGetCertificateChain_Entity_INTERNAL_ERROR() throws Exception {

        mockEntity(EntityType.ENTITY);
        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE)).thenThrow(new PersistenceException());
        certificateChainHelper.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, CertificateStatus.ACTIVE);

    }

    /**
     * Test Case for checking CertificateServiceException is thrown when trying to get active certificate from DB.
     *
     * @throws Exception
     *
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testGetActiveCertificateChain_Entity_UNEXPECTED_ERROR() throws Exception {

        mockEntity(EntityType.ENTITY);
        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE)).thenThrow(new CertificateException());
        certificateChainHelper.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, CertificateStatus.ACTIVE);

    }

    /**
     * Test Case for Retrieving certificate chain list For CAEntity.
     *
     * @throws Exception
     */
    @Test
    public void testGetCertificateChainList_CAEntity_CertificateStatus_Active() throws Exception {

        mockEntity(EntityType.CA_ENTITY);
        mockCAEntityCertificate(CertificateStatus.ACTIVE);
        mockCAEntityCertificateChain(setUPData.getCAEntityCertificate(), CertificateStatus.ACTIVE);

        final List<CertificateChain> actualCertificateChains = certificateChainHelper.getCertificateChainList(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                CertificateStatus.ACTIVE);

        final List<CertificateChain> expectedCertificateChains = setUPData.getCAEntityCertificateChain(CertificateStatus.ACTIVE);

        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    /**
     * Test Case for Retrieving inactive certificate chain For CAEntity.
     *
     * @throws Exception
     */
    @Test
    public void testGetCertificateChainList_CAEntity_CertificateStatus_InActive() throws Exception {

        mockEntity(EntityType.CA_ENTITY);
        mockCAEntityCertificate(CertificateStatus.INACTIVE);

        final Certificate certificate = setUPData.getCAEntityCertificate();
        certificate.setStatus(CertificateStatus.INACTIVE);
        mockCAEntityCertificateChain(certificate, CertificateStatus.INACTIVE);

        final List<CertificateChain> actualCertificateChains = certificateChainHelper.getCertificateChainList(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID,
                CertificateStatus.INACTIVE);

        final List<CertificateChain> expectedCertificateChains = setUPData.getCAEntityCertificateChain(CertificateStatus.INACTIVE);

        assertEquals(expectedCertificateChains, actualCertificateChains);

    }

    @Test(expected = InvalidEntityException.class)
    public void testGetActiveCertificateChain_invalidEntityException() throws Exception {

        mockEntity(EntityType.ENTITY);
        Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE)).thenReturn(null);
        certificateChainHelper.getCertificateChain(SetUPData.ENTITY_NAME, EntityType.ENTITY, CertificateStatus.ACTIVE);

    }

    /**
     * Test Case for checking InvalidCAException is thrown when in the certificate chain list, issuer certificate is revoked or expired.
     *
     * @throws Exception
     */
    @Test(expected = InvalidCAException.class)
    public void testGetCertificateChainList_CAEntity_InvalidCAException() throws Exception {

        mockEntity(EntityType.CA_ENTITY);
        mockCAEntityCertificate(CertificateStatus.INACTIVE);

        final Certificate certificate = setUPData.getCAEntityCertificate();
        certificate.setStatus(CertificateStatus.INACTIVE);
        Mockito.when(certificatePersistenceHelper.getCertificateChain(certificate, Constants.INACTIVE_CERTIFICATE_VALID)).thenReturn(null);
        certificateChainHelper.getCertificateChainList(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.INACTIVE);
    }

    /**
     * Test Case for checking InvalidCAException when the given CAEntity doesn't have an active Certificate.
     *
     * @throws Exception
     */
    @Test(expected = InvalidCAException.class)
    public void testGetCertificateChain_CAEntity_Active_Certificate_Not_Found() throws Exception {

        mockEntity(EntityType.CA_ENTITY);
        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.SUB_CA_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE)).thenReturn(null);
        certificateChainHelper.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, CertificateStatus.ACTIVE);

    }

    /**
     * Test Case for Retrieving active certificate chain For CAEntity.
     *
     * @throws Exception
     */
    @Test
    public void testGetCertificateChain_CAEntity_CertificateStatus_Active() throws Exception {

        mockEntity(EntityType.CA_ENTITY);
        mockCAEntityCertificate(CertificateStatus.ACTIVE);

        final Certificate certificate = setUPData.getCAEntityCertificate();
        certificate.setStatus(CertificateStatus.ACTIVE);
        mockCAEntityCertificateChain(certificate, CertificateStatus.ACTIVE);

        final List<Certificate> actualCertificates = certificateChainHelper.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, CertificateStatus.ACTIVE);

        final List<Certificate> expectedCertificates = setUPData.getCAEntityCertificates(CertificateStatus.ACTIVE);

        assertEquals(actualCertificates, expectedCertificates);
    }

    /**
     * Test Case for Retrieving inactive certificate chain For CAEntity.
     *
     * @throws Exception
     */
    @Test
    public void testGetCertificateChain_CAEntity_CertificateStatus_InActive() throws Exception {

        mockEntity(EntityType.CA_ENTITY);
        mockCAEntityCertificate(CertificateStatus.INACTIVE);

        final Certificate certificate = setUPData.getCAEntityCertificate();
        certificate.setStatus(CertificateStatus.INACTIVE);
        mockCAEntityCertificateChain(certificate, CertificateStatus.INACTIVE);

        final List<Certificate> actualCertificates = certificateChainHelper.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, CertificateStatus.INACTIVE);

        final List<Certificate> expectedCertificates = setUPData.getCAEntityCertificates(CertificateStatus.INACTIVE);

        assertEquals(actualCertificates, expectedCertificates);

    }

    /**
     * Test Case for checking InvalidCAException is thrown when in the certificate chain, issuer certificate is revoked or expired.
     *
     * @throws Exception
     */
    @Test(expected = InvalidCAException.class)
    public void testGetCertificateChain_CAEntity_InvalidCAException() throws Exception {

        mockEntity(EntityType.CA_ENTITY);
        mockCAEntityCertificate(CertificateStatus.INACTIVE);

        final Certificate certificate = setUPData.getCAEntityCertificate();
        certificate.setStatus(CertificateStatus.INACTIVE);

        Mockito.when(certificatePersistenceHelper.getCertificateChain(certificate, Constants.INACTIVE_CERTIFICATE_VALID)).thenReturn(null);

        certificateChainHelper.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, CertificateStatus.INACTIVE);

    }

    /**
     * Test Case for InvalidCAException when the given CAEntity doesn't have an inactive Certificate.
     *
     * @throws Exception
     */
    @Test(expected = InvalidCAException.class)
    public void testGetCertificateChain_CAEntity_InActive_Certificate_Not_Found() throws Exception {

        mockEntity(EntityType.CA_ENTITY);
        Mockito.when(caPersistenceHelper.getCertificates(SetUPData.SUB_CA_NAME, MappingDepth.LEVEL_0, CertificateStatus.INACTIVE)).thenReturn(null);
        certificateChainHelper.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, CertificateStatus.INACTIVE);

    }

    /**
     * Test Case for checking InvalidCAException is thrown when the issuer certificate of given CAEntity doesn't have an active and inactive Certificate.
     *
     * @throws Exception
     */
    @Test(expected = InvalidCAException.class)
    public void testGetCertificateChain_CAEntity_Issuer_Certificate_Revoked() throws Exception {

        mockEntity(EntityType.CA_ENTITY);
        mockCAEntityCertificate(CertificateStatus.ACTIVE);
        Mockito.when(certificatePersistenceHelper.getCertificateChain(setUPData.getCAEntityCertificate(), Constants.INACTIVE_CERTIFICATE_VALID)).thenThrow(
                new InvalidCAException(ErrorMessages.ISSUER_CERITICATE_IS_REVOKED_OR_EXPIRED));
        certificateChainHelper.getCertificateChain(SetUPData.SUB_CA_NAME, EntityType.CA_ENTITY, CertificateStatus.ACTIVE);

    }

    private void mockCAEntityCertificate(final CertificateStatus certificateStatus) throws CertificateException, IOException {

        final List<Certificate> caEntitycertificates = new ArrayList<Certificate>();
        final Certificate caEntityCertificate = setUPData.getCAEntityCertificate();

        if (certificateStatus.equals(CertificateStatus.ACTIVE)) {
            caEntitycertificates.add(caEntityCertificate);
            Mockito.when(caPersistenceHelper.getCertificates(SetUPData.SUB_CA_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE)).thenReturn(caEntitycertificates);

        } else {
            caEntityCertificate.setStatus(CertificateStatus.INACTIVE);
            caEntitycertificates.add(caEntityCertificate);
            Mockito.when(caPersistenceHelper.getCertificates(SetUPData.SUB_CA_NAME, MappingDepth.LEVEL_0, CertificateStatus.INACTIVE)).thenReturn(caEntitycertificates);

        }

    }

    private void mockEntity(final EntityType entityType) throws DatatypeConfigurationException, CertificateException, IOException {

        if (entityType.equals(EntityType.CA_ENTITY)) {
            final CAEntity caEntity = entitySetUPData.getCAEntity();
            Mockito.when(entityHelper.getCAEntity(SetUPData.SUB_CA_NAME)).thenReturn(caEntity);
        } else {
            final Entity entity = entitySetUPData.getEntity();
            Mockito.when(entityHelper.getEntity(SetUPData.ENTITY_NAME)).thenReturn(entity);
        }

    }

    private void mockEntityCertificate(final CertificateStatus certificateStatus) throws CertificateException, IOException {

        final List<Certificate> entityCertificates = new ArrayList<Certificate>();

        if (certificateStatus.equals(CertificateStatus.ACTIVE)) {
            final Certificate entityCertificate = setUPData.getEntityCertificate();
            entityCertificates.add(entityCertificate);
            Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE)).thenReturn(entityCertificates);

        } else {

            final Certificate entityCertificate = setUPData.getEntityCertificate();
            entityCertificate.setStatus(CertificateStatus.INACTIVE);
            entityCertificates.add(entityCertificate);
            Mockito.when(entityPersistenceHelper.getCertificates(SetUPData.ENTITY_NAME, MappingDepth.LEVEL_0, CertificateStatus.INACTIVE)).thenReturn(entityCertificates);

        }

    }

    private void mockEntityCertificateChain(final Certificate certificate, final CertificateStatus certificateStatus) throws InvalidCAException, CertificateException, IOException {

        List<Certificate> certificates = null;

        if (certificateStatus == CertificateStatus.ACTIVE) {
            certificates = setUPData.getEntityCertificateChain(CertificateStatus.ACTIVE).get(0).getCertificates();
        } else {
            certificates = setUPData.getEntityCertificateChain(CertificateStatus.INACTIVE).get(0).getCertificates();
        }

        Mockito.when(certificatePersistenceHelper.getCertificateChain(certificate, Constants.INACTIVE_CERTIFICATE_VALID)).thenReturn(certificates);

    }

    private void mockCAEntityCertificateChain(final Certificate certificate, final CertificateStatus certificateStatus) throws InvalidCAException, CertificateException, IOException {

        List<Certificate> certificates = null;
        if (certificateStatus == CertificateStatus.ACTIVE) {
            certificates = setUPData.getCAEntityCertificateChain(CertificateStatus.ACTIVE).get(0).getCertificates();
        } else {
            certificates = setUPData.getCAEntityCertificateChain(CertificateStatus.INACTIVE).get(0).getCertificates();
        }
        Mockito.when(certificatePersistenceHelper.getCertificateChain(certificate, Constants.INACTIVE_CERTIFICATE_VALID)).thenReturn(certificates);

    }
}
