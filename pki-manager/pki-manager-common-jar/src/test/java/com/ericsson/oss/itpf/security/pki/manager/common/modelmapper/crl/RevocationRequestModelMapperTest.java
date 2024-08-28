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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl;

import static org.junit.Assert.*;

import java.security.cert.CertificateEncodingException;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class RevocationRequestModelMapperTest {

    @InjectMocks
    RevocationRequestModelMapper revocationRequestModelMapper;

    @Mock
    CAEntityMapper caEntityMapper;

    @Mock
    EntityMapper entityMapper;

    @Mock
    CertificateModelMapper certificateModelMapper;

    private RevocationRequestData revocationRequestData;
    private Date date;
    private CAEntity caEntity;
    private Certificate entity_certificate;
    private List<Certificate> certificateList;
    private CertificateAuthority certificateAuthority;
    private CAEntityData caEntityData;
    private RevocationRequest revocationRequest;
    private EntityData entityData;
    private List<CertificateData> certificataDataList;
    private CertificateData certificateData;

    /**
     * 
     */
    @Before
    public void setUp() {

        date = new Date();

        entity_certificate = new Certificate();
        entity_certificate.setId(10101);
        entity_certificate.setIssuedTime(date);
        entity_certificate.setSerialNumber("35464474");
        entity_certificate.setStatus(CertificateStatus.ACTIVE);

        certificateList = new LinkedList<Certificate>();
        certificateList.add(entity_certificate);

        caEntityData = new CAEntityData();
        caEntityData.setId(345678);

        revocationRequestData = new RevocationRequestData();
        revocationRequestData.setId(1010101);

        final CrlEntryExtensions crlEntryExtensions = new CrlEntryExtensions();

        final InvalidityDate invalidityDateObject = new InvalidityDate();
        invalidityDateObject.setInvalidityDate(new Date());
        crlEntryExtensions.setInvalidityDate(invalidityDateObject);

        revocationRequestData.setCrlEntryExtensionsJSONData(JsonUtil.getJsonFromObject(crlEntryExtensions));

        revocationRequestData.setCaEntity(caEntityData);

        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(345678);
        certificateAuthority.setName("CAName");
        certificateAuthority.setRootCA(false);

        revocationRequest = new RevocationRequest();
        revocationRequest.setCaEntity(certificateAuthority);
        revocationRequest.setCertificatesToBeRevoked(certificateList);

        final CrlEntryExtensions crlEntryExtensionsKC = new CrlEntryExtensions();

        final InvalidityDate invalidityDateObjectKC = new InvalidityDate();
        invalidityDateObjectKC.setInvalidityDate(new Date());
        crlEntryExtensionsKC.setInvalidityDate(invalidityDateObjectKC);

        final ReasonCode reasonCodeObject = new ReasonCode();
        reasonCodeObject.setRevocationReason(RevocationReason.KEY_COMPROMISE);
        crlEntryExtensionsKC.setReasonCode(reasonCodeObject);

        revocationRequest.setCrlEntryExtensions(crlEntryExtensionsKC);

        entityData = new EntityData();
        entityData.setId(34546);

        caEntity = new CAEntity();
        caEntity.setCertificateAuthority(certificateAuthority);

        certificataDataList = new LinkedList<CertificateData>();

        certificateData = new CertificateData();
        certificateData.setId(10101);
        certificateData.setIssuerCA(caEntityData);

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.RevocationRequestModelMapper#toAPIModel(com.ericsson.oss.itpf.security.pki.manager.persistence.entities.RevocationRequestData)}
     * .
     */
    @Test
    public void testToAPIModel() {

        Mockito.when(caEntityMapper.toAPIFromModel(revocationRequestData.getCaEntity())).thenReturn(caEntity);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certificataDataList)).thenReturn(certificateList);
            final RevocationRequest request = revocationRequestModelMapper.toAPIModel(revocationRequestData);
            assertJPAWithToAPIModel(request, revocationRequestData);

        } catch (Exception e) {

        }
    }

    /**
     * This method will assert RevocationRequestData JPA object with Revocation request model
     * 
     * @param revocationRequestData
     *            - JPA object
     * @param revocationRequest
     *            - API model
     * 
     */
    private void assertJPAWithToAPIModel(final RevocationRequest request, final RevocationRequestData revocationRequestData) {
        assertNotNull(request);
        assertEquals(request.getEntity().getId(), revocationRequestData.getEntity().getId());
        assertEquals(request.getCertificatesToBeRevoked().size(), revocationRequestData.getCertificatesToRevoke().size());
        assertEquals(request.getCaEntity().getId(), revocationRequestData.getCaEntity().getId());
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.RevocationRequestModelMapper#fromAPIModel(com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequest)}
     * .
     */
    @Test
    public void testFromAPIModel() {

        try {

            Mockito.when(caEntityMapper.fromAPIToModel(revocationRequest.getCaEntity())).thenReturn(caEntityData);
            Mockito.when(entityMapper.fromAPIToModel(revocationRequest.getEntity())).thenReturn(entityData);
            Mockito.when(certificateModelMapper.fromObjectModel(entity_certificate)).thenReturn(certificateData);
            final RevocationRequestData rData = revocationRequestModelMapper.fromAPIModel(revocationRequest);
            assertJPAWithFromAPIModel(rData, revocationRequest);
        } catch (CertificateEncodingException e) {

        }
    }

    /**
     * This method will assert RevocationRequestData JPA object with Revocation request model
     * 
     * @param revocationRequestData
     *            - JPA object
     * @param revocationRequest
     *            - API model
     * 
     */
    private void assertJPAWithFromAPIModel(final RevocationRequestData revocationRequestData, final RevocationRequest revocationRequest) {
        assertNotNull(revocationRequestData);
        assertEquals(revocationRequestData.getCaEntity().getId(), revocationRequest.getCaEntity().getId());
        assertEquals(revocationRequestData.getCrlEntryExtensionsJSONData(), JsonUtil.getJsonFromObject(revocationRequest.getCrlEntryExtensions()));
        assertEquals(revocationRequestData.getCertificatesToRevoke().iterator().next().getId(), revocationRequest.getCertificatesToBeRevoked().get(0).getId());
    }
}
