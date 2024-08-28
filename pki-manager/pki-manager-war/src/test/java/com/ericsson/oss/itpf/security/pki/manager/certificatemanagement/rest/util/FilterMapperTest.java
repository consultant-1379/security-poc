package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.CertificateResourceHelper;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;

@RunWith(MockitoJUnitRunner.class)
public class FilterMapperTest {

    @InjectMocks
    FilterMapper filterMapper;

    @Spy
    Logger logger = LoggerFactory.getLogger(CertificateResourceHelper.class);

    FilterDTO filterDTO;
    CertificateDTO certificateDTO;
    SetUPData setUPData;

    private final static CertificateStatus certificatestatus = CertificateStatus.ACTIVE;
    private static final EntityType entityType = EntityType.CA_ENTITY;

    @Before
    public void setUp() throws Exception {

        filterDTO = new FilterDTO();
        certificateDTO = new CertificateDTO();
        setUPData = new SetUPData();
        filterDTO.setSubject("MyRoot");
        filterDTO.setIssuer("MyRoot");
        CertificateStatus[] certStatus = new CertificateStatus[1];
        for (int i = 0; i < 1; i++) {
            certStatus[i] = certificatestatus;
        }
        filterDTO.setStatus(certStatus);
        EntityType[] entityTypes = new EntityType[1];
        for (int i = 0; i < 1; i++) {
            entityTypes[i] = entityType;
        }

        filterDTO.setType(entityTypes);
        certificateDTO.setFilter(filterDTO);
    }

    @Test
    public void testToCertificateFilter() throws Exception {

        filterMapper.toCertificateFilter(filterDTO);

    }

    @Test
    public void testToCertificateFilter_filterDTONull() throws Exception {

        filterDTO = new FilterDTO();
        filterDTO = null;

        filterMapper.toCertificateFilter(filterDTO);

    }

    @Test
    public void testToCertificateFilter_CertificateDTO() throws Exception {

        filterMapper.toCertificateFilter(certificateDTO);

    }

    @Test
    public void testToCertificateFilterForLoad() throws Exception {

        final Long[] certificateIds = new Long[1];

        filterMapper.toCertificateFilterForLoad(certificateIds);

    }

    @Test
    public void toCertificateFilter() {

        final DownloadDTO downloadDTO = setUPData.getDownloadDTO();

        final CertificateFilter certificateFilter = filterMapper.toCertificateFilter(downloadDTO);
        assertNotNull(certificateFilter);
        assertEquals(downloadDTO.getCertificateIds(), certificateFilter.getCertificateIdList());

    }

}
