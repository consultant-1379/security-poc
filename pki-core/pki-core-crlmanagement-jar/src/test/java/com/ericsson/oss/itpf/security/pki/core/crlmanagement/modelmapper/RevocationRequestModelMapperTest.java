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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.modelmapper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.cert.CertificateException;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension.CrlEntryExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.util.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException;

@RunWith(MockitoJUnitRunner.class)
public class RevocationRequestModelMapperTest extends BaseTest {

    @InjectMocks
    RevocationRequestModelMapper revocationRequestModelMapper;

    @Mock
    CertificateAuthorityModelMapper caEntityMapper;

    @Mock
    EntityModelMapper entityMapper;

    @Mock
    CertificateModelMapper certificateMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    private Logger logger;

    private static RevocationRequestData revocationRequestDataForCaEntity;
    private static RevocationRequestData revocationRequestDataForEntity;
    private static RevocationRequest revocationRequestForCaEntity;
    private static RevocationRequest revocationRequestForEntity;
    private static Certificate certificate;
    private static CertificateData certificateData;
    private static List<Certificate> certificateList = new ArrayList<Certificate>();
    private static List<CertificateData> certificateDataList = new ArrayList<CertificateData>();
    private static Map<String, Object> mapCertificate = new HashMap<String, Object>();

    /**
     * Method to test {@link RevocationRequestData} to API {@link RevocationRequest} for CaEntity
     *
     */
    @Before
    public void Setup() {
        certificateData = prepareCertificateData(111, "1001");
        certificateDataList.clear();
        certificateDataList.add(certificateData);

        certificate = prepareCertificate(111, "1001");
        certificateList.clear();
        certificateList.add(certificate);

        revocationRequestDataForCaEntity = prepareRevocationRequestDataWithCaEntity();
        revocationRequestDataForCaEntity.getCertificatesToRevoke().add(certificateData);

        revocationRequestDataForEntity = prepareRevocationRequestDataWithEntity();
        revocationRequestDataForEntity.getCertificatesToRevoke().add(certificateData);

        revocationRequestForCaEntity = prepareRevocationrequestForCaEntity();
        revocationRequestForCaEntity.setCertificatesToBeRevoked(certificateList);

        revocationRequestForEntity = prepareRevocationrequestForEntity();
        revocationRequestForEntity.setCertificatesToBeRevoked(certificateList);

        mapCertificate.put("serialNumber", certificate.getSerialNumber());
        mapCertificate.put("issuerCA", prepareCertificateAuthorityData(555, "ENMROOTCA"));
    }

    @Test
    public void testToAPIModelForCaEntity() throws CertificateException {
        Mockito.when(caEntityMapper.toAPIModel(revocationRequestDataForCaEntity.getCaEntity())).thenReturn(prepareCertificateAuthority(101, "ENMSUBCA"));
        final RevocationRequest revocationRequest = revocationRequestModelMapper.toAPIModel(revocationRequestDataForCaEntity);
        assertNotNull(revocationRequest);
        assertAPIModelWithJPAForCaEntity(revocationRequest, revocationRequestDataForCaEntity);
    }

    /**
     * Method to test {@link RevocationRequestData} to API {@link RevocationRequest} for Entity
     *
     * @throws CertificateException
     *
     */
    @Test
    public void testToAPIModelForEntity() throws CertificateException {
        Mockito.when(entityMapper.toAPIFromModel(revocationRequestDataForEntity.getEntity())).thenReturn(prepareEntityInfo(1001, "Entity1"));
        final RevocationRequest revocationRequest = revocationRequestModelMapper.toAPIModel(revocationRequestDataForEntity);
        assertNotNull(revocationRequest);
        assertJPAWithAPIForEntity(revocationRequest, revocationRequestDataForEntity);
    }

    /**
     * Method to test {@link RevocationServiceException} when {@link CertificateException} is thrown
     *
     * @throws CertificateException
     */
    @Test(expected = RevocationServiceException.class)
    public void testToApiModelForEntity_RevocationServiceException() throws CertificateException {
        final List<Certificate> certificateList = new ArrayList<Certificate>();
        certificateData = prepareCertificateData(111, "1001");
        revocationRequestDataForEntity.getCertificatesToRevoke().add(certificateData);
        revocationRequestDataForEntity.setCaEntity(prepareCertificateAuthorityData(10101L, "ENM_CA"));
        Mockito.when(certificateList.add(certificateMapper.mapToCertificate(certificateData))).thenThrow(new CertificateException(ErrorMessages.INTERNAL_ERROR));
        revocationRequestModelMapper.toAPIModel(revocationRequestDataForEntity);
    }

    /**
     * Method to test {@link RevocationRequest} API model to {@link RevocationRequestData} JPA object for CAEntity
     *
     */
    @Test
    public void testFromAPIModelForCaEntity() {
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, revocationRequestForCaEntity.getCaEntity().getName(), "name")).thenReturn(
                prepareCertificateAuthorityData(101, "ENMSUBCA"));
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, certificate.getIssuer().getName(), Constants.NAME_PATH)).thenReturn(
                prepareCertificateAuthorityData(555, "ENMROOTCA"));
        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, mapCertificate)).thenReturn(certificateDataList);
        final RevocationRequestData revocationRequestData = revocationRequestModelMapper.fromAPIModel(revocationRequestForCaEntity);
        assertNotNull(revocationRequestData);
        assertJPAWithAPIModelForCaEntity(revocationRequestForCaEntity, revocationRequestData);
    }

    /**
     * Method to test {@link RevocationRequest} API model to {@link RevocationRequestData} JPA object for Entity
     *
     */
    @Test
    public void testFromAPIModelForEntity() {
        Mockito.when(persistenceManager.findEntityByName(EntityInfoData.class, revocationRequestForEntity.getEntity().getName(), "name")).thenReturn(prepareEntityInfoData(1001, "Entity1"));
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, certificate.getIssuer().getName(), Constants.NAME_PATH)).thenReturn(
                prepareCertificateAuthorityData(555, "ENMROOTCA"));
        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, mapCertificate)).thenReturn(certificateDataList);
        final RevocationRequestData revocationRequestData = revocationRequestModelMapper.fromAPIModel(revocationRequestForEntity);
        assertNotNull(revocationRequestData);
        assertAPIModelWithJPAForEntity(revocationRequestForEntity, revocationRequestData);
    }

    /**
     * This method will assert RevocationRequestData JPA object with Revocation request model
     *
     * @param revocationRequest
     *            - API model
     * @param revocationRequestData
     *            - JPA object
     */
    private void assertAPIModelWithJPAForEntity(final RevocationRequest revocationRequest, final RevocationRequestData revocationRequestData) {
        assertEquals(revocationRequest.getCaEntity(), revocationRequestData.getCaEntity());
        assertEquals(revocationRequest.getEntity().getId(), revocationRequestData.getEntity().getId());
        assertEquals(revocationRequest.getEntity().getName(), revocationRequestData.getEntity().getName());
        assertEquals(revocationRequest.getCrlEntryExtensions(), JsonUtil.getObjectFromJson(CrlEntryExtensions.class, revocationRequestData.getCrlEntryExtensionsJSONData()));
        assertEquals(revocationRequest.getCertificatesToBeRevoked().size(), revocationRequestData.getCertificatesToRevoke().size());
    }

    /**
     * This method will assert revocationRequest API object with revocationRequestData JPA object
     *
     * @param revocationRequest
     *            - API model
     * @param revocationRequestData
     *            - JPA object
     */
    private void assertJPAWithAPIForEntity(final RevocationRequest revocationRequest, final RevocationRequestData revocationRequestData) {
        assertEquals(revocationRequestData.getCaEntity(), revocationRequest.getCaEntity());
        assertEquals(revocationRequestData.getEntity().getId(), revocationRequest.getEntity().getId());
        assertEquals(revocationRequestData.getEntity().getName(), revocationRequest.getEntity().getName());
        assertEquals(revocationRequestData.getCrlEntryExtensionsJSONData(), JsonUtil.getJsonFromObject(revocationRequest.getCrlEntryExtensions()));
        assertEquals(revocationRequestData.getCertificatesToRevoke().size(), revocationRequest.getCertificatesToBeRevoked().size());
    }

    /**
     * This method will assert RevocationRequestData JPA object with Revocation request model
     *
     * @param revocationRequest
     *            - API model
     * @param revocationRequestData
     *            - JPA object
     */
    private void assertAPIModelWithJPAForCaEntity(final RevocationRequest revocationRequest, final RevocationRequestData revocationRequestData) {
        assertEquals(revocationRequest.getCaEntity().getId(), revocationRequestData.getCaEntity().getId());
        assertEquals(revocationRequest.getCaEntity().getName(), revocationRequestData.getCaEntity().getName());
        assertEquals(revocationRequest.getEntity(), revocationRequestData.getEntity());
        assertEquals(revocationRequest.getCrlEntryExtensions(), JsonUtil.getObjectFromJson(CrlEntryExtensions.class, revocationRequestData.getCrlEntryExtensionsJSONData()));
        assertEquals(revocationRequest.getCertificatesToBeRevoked().size(), revocationRequestData.getCertificatesToRevoke().size());
    }

    /**
     * This method will assert revocationRequest API object with revocationRequestData JPA object
     *
     * @param revocationRequest
     *            - API model
     * @param revocationRequestData
     *            - JPA object
     */
    private void assertJPAWithAPIModelForCaEntity(final RevocationRequest revocationRequest, final RevocationRequestData revocationRequestData) {
        assertEquals(revocationRequestData.getCaEntity().getId(), revocationRequest.getCaEntity().getId());
        assertEquals(revocationRequestData.getCaEntity().getName(), revocationRequest.getCaEntity().getName());
        assertEquals(revocationRequestData.getEntity(), revocationRequest.getEntity());
        assertEquals(revocationRequestData.getCrlEntryExtensionsJSONData(), JsonUtil.getJsonFromObject(revocationRequest.getCrlEntryExtensions()));
        assertEquals(revocationRequestData.getCertificatesToRevoke().size(), revocationRequest.getCertificatesToBeRevoked().size());
    }
}
