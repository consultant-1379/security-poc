package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.validation;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.validator.input.InputValidator;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.rest.exception.InvalidArgumentException;

@RunWith(MockitoJUnitRunner.class)
public class InputValidatorTest {

    @InjectMocks
    InputValidator inputValidator;

    @Mock
    Logger logger;

    private static FilterDTO filterDTO;
    private static CertificateDTO certificateDTO;
    private static SetUPData setUPData;

    private final static CertificateStatus certificatestatus = CertificateStatus.ACTIVE;
    private static final EntityType entityType = EntityType.CA_ENTITY;

    @Before
    public void setUp() throws Exception {

        certificateDTO = new CertificateDTO();
        filterDTO = new FilterDTO();
        setUPData = new SetUPData();
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

    }

    @Test
    public void testValidateFilterDTO() {

        final boolean validFilter = inputValidator.validateFilterDTO(filterDTO);

        Assert.assertEquals(true, validFilter);
    }

    @Test
    public void testValidate() {

        certificateDTO.setFilter(filterDTO);
        certificateDTO.setLimit(1);
        certificateDTO.setOffset(1);

        final boolean validFilter = inputValidator.validate(certificateDTO);

        Assert.assertEquals(true, validFilter);
    }

    @Test(expected = InvalidArgumentException.class)
    public void testValidate_LimitNull() {

        certificateDTO.setFilter(filterDTO);
        certificateDTO.setLimit(null);
        certificateDTO.setOffset(1);

        inputValidator.validate(certificateDTO);
    }

    @Test(expected = InvalidArgumentException.class)
    public void testValidate_OffsetNull() {

        certificateDTO.setFilter(filterDTO);
        certificateDTO.setLimit(1);
        certificateDTO.setOffset(null);

        inputValidator.validate(certificateDTO);
    }

    @Test(expected = InvalidArgumentException.class)
    public void testValidate_OffsetLimitNull() {

        certificateDTO.setFilter(filterDTO);
        certificateDTO.setLimit(null);
        certificateDTO.setOffset(null);

        inputValidator.validate(certificateDTO);
    }

    @Test
    public void testValidateFilterDTO_CertificateStatusNull() {

        filterDTO = new FilterDTO();

        EntityType[] entityTypes = new EntityType[1];
        for (int i = 0; i < 1; i++) {
            entityTypes[i] = entityType;
        }

        filterDTO.setType(entityTypes);

        final boolean validFilter = inputValidator.validateFilterDTO(filterDTO);

        Assert.assertEquals(false, validFilter);
    }

    @Test
    public void testValidateFilterDTO_filterDTONull() {

        filterDTO = new FilterDTO();

        filterDTO = null;

        final boolean validFilter = inputValidator.validateFilterDTO(filterDTO);

        Assert.assertEquals(true, validFilter);
    }

    @Test(expected = InvalidArgumentException.class)
    public void testValidate_OffsetLimitZero() {

        certificateDTO.setFilter(filterDTO);
        certificateDTO.setLimit(0);
        certificateDTO.setOffset(0);

        inputValidator.validate(certificateDTO);
    }

    @Test
    public void testValidateFilterDTO_EntityTypeNull() {

        filterDTO = new FilterDTO();

        CertificateStatus[] certStatus = new CertificateStatus[1];
        for (int i = 0; i < 1; i++) {
            certStatus[i] = certificatestatus;
        }
        filterDTO.setStatus(certStatus);

        final boolean validFilter = inputValidator.validateFilterDTO(filterDTO);

        Assert.assertEquals(false, validFilter);
    }

    @Test
    public void testValidateDownloadDTO() {

        final DownloadDTO downloadDTO = setUPData.getDownloadDTO();
        inputValidator.validateDownloadDTO(downloadDTO);

    }

    @Test(expected = InvalidArgumentException.class)
    public void testValidateDownloadDTO_ID_Null() {

        final DownloadDTO downloadDTO = setUPData.getDownloadDTO();
        downloadDTO.setCertificateIds(null);
        inputValidator.validateDownloadDTO(downloadDTO);

    }

    @Test(expected = InvalidArgumentException.class)
    public void testValidateDownloadDTO_Format_Null() {

        final DownloadDTO downloadDTO = setUPData.getDownloadDTO();
        downloadDTO.setFormat(null);
        inputValidator.validateDownloadDTO(downloadDTO);

    }

    @Test
    public void testValidateFileDTO() {

        final KeyStoreFileDTO keyStoreFileDTO = setUPData.getKeyStoreFileDTO();
        inputValidator.validateFileDTO(keyStoreFileDTO);
    }

    @Test(expected = InvalidArgumentException.class)
    public void testValidateFileDTO_Name_Null() {

        final KeyStoreFileDTO keyStoreFileDTO = setUPData.getKeyStoreFileDTO();
        keyStoreFileDTO.setName(null);
        inputValidator.validateFileDTO(keyStoreFileDTO);
    }

    @Test(expected = InvalidArgumentException.class)
    public void testValidateFileDTO_Data_Null() {

        final KeyStoreFileDTO keyStoreFileDTO = setUPData.getKeyStoreFileDTO();
        keyStoreFileDTO.setData(null);
        inputValidator.validateFileDTO(keyStoreFileDTO);
    }

    @Test(expected = InvalidArgumentException.class)
    public void testValidateFileDTO_Format_Null() {

        final KeyStoreFileDTO keyStoreFileDTO = setUPData.getKeyStoreFileDTO();
        keyStoreFileDTO.setFormat(null);
        inputValidator.validateFileDTO(keyStoreFileDTO);
    }

    @Test
    public void validateCAReissueDTO() {
        final CAReissueDTO caReissueDTO = setUPData.getCAReissueDTO();
        inputValidator.validateCAReissueDTO(caReissueDTO);
    }

    @Test(expected = InvalidArgumentException.class)
    public void validateCAReissueDTO_CAName_Null() {

        final CAReissueDTO caReissueDTO = setUPData.getCAReissueDTO();
        caReissueDTO.setName(null);
        inputValidator.validateCAReissueDTO(caReissueDTO);

    }

    @Test(expected = InvalidArgumentException.class)
    public void validateCAReissueDTO_ReIssueType_Null() {

        final CAReissueDTO caReissueDTO = setUPData.getCAReissueDTO();
        caReissueDTO.setReIssueType(null);
        inputValidator.validateCAReissueDTO(caReissueDTO);

    }

    @Test
    public void validateEntityReissueDTO() {
        final EntityReissueDTO entityReissueDTO = setUPData.getEntityReissueDTO();
        inputValidator.validateEntityReissueDTO(entityReissueDTO);
    }

    @Test(expected = InvalidArgumentException.class)
    public void validateEntityReissueDTO_EndEntityName_Null() {
        final EntityReissueDTO entityReissueDTO = setUPData.getEntityReissueDTO();
        entityReissueDTO.setName(null);
        inputValidator.validateEntityReissueDTO(entityReissueDTO);
    }

    @Test(expected = InvalidArgumentException.class)
    public void validateEntityReissueDTO_Format_Null() {
        final EntityReissueDTO entityReissueDTO = setUPData.getEntityReissueDTO();
        entityReissueDTO.setFormat(null);
        inputValidator.validateEntityReissueDTO(entityReissueDTO);
    }
}
