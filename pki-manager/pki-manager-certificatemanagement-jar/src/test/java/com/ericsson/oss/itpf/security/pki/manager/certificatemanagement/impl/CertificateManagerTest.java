package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl;

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.EnumSet;

import javax.persistence.PersistenceException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator.CertificateFilterValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.EntityTypeFilter;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.FilterResponseType;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagerTest {

    @InjectMocks
    CertificateManager certificateManager;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    CertificateFilterValidator certificateFilterValidator;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Mock
    Logger logger;

    private static SetUPData setUPData;
    private static CertificateFilter certificateFilter;
    private static EntityType[] entityTypes;
    private static EnumSet<EntityType> entityTypeFilter;
    private static CertificateData certificateData;
    private static final EntityType entityType = EntityType.CA_ENTITY;

    @BeforeClass
    public static void setUP() throws CertificateException, IOException {

        setUPData = new SetUPData();
        certificateFilter = new CertificateFilter();
        certificateFilter.setLimit(1);
        certificateFilter.setOffset(1);
        entityTypes = new EntityType[1];
        for (int i = 0; i < 1; i++) {
            entityTypes[i] = entityType;
        }
        certificateFilter.setEntityTypes(entityTypes);
        entityTypeFilter = EntityTypeFilter.getEntityType(certificateFilter.getEntityTypes());
        certificateData = setUPData.createCertificateData("1223456");

    }

    @Test
    public void testGetCertificates() throws Exception {

        Mockito.when(certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, FilterResponseType.LIST)).thenReturn(Arrays.asList(certificateData));
        certificateManager.getCertificates(certificateFilter);

    }

    @Test(expected = CertificateServiceException.class)
    public void testListCertificates_IOException() throws Exception {

        Mockito.when(certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, FilterResponseType.LIST)).thenReturn(Arrays.asList(certificateData));
        Mockito.when(certificateModelMapper.toObjectModel(Mockito.anyList(), Mockito.anyBoolean())).thenThrow(new IOException(UNEXPECTED_ERROR));

        certificateManager.getCertificates(certificateFilter);
    }

    @Test(expected = CertificateServiceException.class)
    public void testListCertificates_CertificateException() throws Exception {

        Mockito.when(certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, FilterResponseType.LIST)).thenReturn(Arrays.asList(certificateData));
        Mockito.when(certificateModelMapper.toObjectModel(Mockito.anyList(), Mockito.anyBoolean())).thenThrow(new CertificateException(UNEXPECTED_ERROR));

        certificateManager.getCertificates(certificateFilter);
    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificates_PersistenceException() throws Exception {

        Mockito.when(certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, FilterResponseType.LIST)).thenThrow(new PersistenceException(INTERNAL_ERROR));
        certificateManager.getCertificates(certificateFilter);

    }

    @Test
    public void testGetCertificateCount() throws Exception {

        Mockito.when(certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, FilterResponseType.COUNT)).thenReturn(BigInteger.valueOf(1));
        certificateManager.getCertificateCount(certificateFilter);

    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificateCount_PersistenceException() throws Exception {

        Mockito.when(certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, FilterResponseType.COUNT)).thenThrow(new PersistenceException(INTERNAL_ERROR));
        certificateManager.getCertificateCount(certificateFilter);

    }

}
