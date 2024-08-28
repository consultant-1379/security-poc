/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.tdps.rest.validator;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.tdps.api.TrustDistributionParameters;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;
import com.ericsson.oss.itpf.security.tdps.rest.exceptions.*;

@RunWith(MockitoJUnitRunner.class)
public class TrustDistributionParamsValidatorTest {

    @InjectMocks
    TrustDistributionParamsValidator trustDistributionParamsValidator;

    @Mock
    TrustDistributionParameters trustDistributionParameters;

    @Test
    public void testValidate() {
        trustDistributionParameters = new TrustDistributionParameters();
        trustDistributionParameters.setCertificateSerialId("123");
        trustDistributionParameters.setCertificateStatus("Active");
        trustDistributionParameters.setEntityName("xyz");
        trustDistributionParameters.setEntityType("CA_Entity");
        trustDistributionParameters.setIssuerName("NE_OAM_CA");
        trustDistributionParamsValidator.validate(trustDistributionParameters);
    }

    @Test(expected = MissingMandatoryParamException.class)
    public void testValidateSerialIdNull() {
        Mockito.when(trustDistributionParameters.getCertificateSerialId()).thenReturn(null);

        trustDistributionParamsValidator.validate(trustDistributionParameters);
    }

    @Test(expected = MissingMandatoryParamException.class)
    public void testValidateEntityNameNull() {
        Mockito.when(trustDistributionParameters.getCertificateSerialId()).thenReturn("1");
        Mockito.when(trustDistributionParameters.getEntityName()).thenReturn(null);

        trustDistributionParamsValidator.validate(trustDistributionParameters);
    }

    @Test(expected = MissingMandatoryParamException.class)
    public void testValidateIssuerNameNull() {
        Mockito.when(trustDistributionParameters.getCertificateSerialId()).thenReturn("1");
        Mockito.when(trustDistributionParameters.getEntityName()).thenReturn("ENTITY");
        Mockito.when(trustDistributionParameters.getIssuerName()).thenReturn(null);

        trustDistributionParamsValidator.validate(trustDistributionParameters);
    }

    @Test(expected = MissingMandatoryParamException.class)
    public void testValidateCertificateStatusNull() {
        Mockito.when(trustDistributionParameters.getCertificateSerialId()).thenReturn("1");
        Mockito.when(trustDistributionParameters.getEntityName()).thenReturn("ENTITY");
        Mockito.when(trustDistributionParameters.getIssuerName()).thenReturn("Issuer");

        Mockito.when(trustDistributionParameters.getCertificateStatus()).thenReturn(null);

        trustDistributionParamsValidator.validate(trustDistributionParameters);
    }

    @Test(expected = MissingMandatoryParamException.class)
    public void testValidateEntityTypeNull() {
        Mockito.when(trustDistributionParameters.getCertificateSerialId()).thenReturn("1");
        Mockito.when(trustDistributionParameters.getEntityName()).thenReturn("ENTITY");
        Mockito.when(trustDistributionParameters.getIssuerName()).thenReturn("Issuer");

        Mockito.when(trustDistributionParameters.getCertificateStatus()).thenReturn("status");
        Mockito.when(trustDistributionParameters.getEntityType()).thenReturn(null);

        trustDistributionParamsValidator.validate(trustDistributionParameters);
    }

    @Test(expected = InvalidEntityException.class)
    public void testValidateInvalidEntityException() {

        Mockito.when(trustDistributionParameters.getCertificateSerialId()).thenReturn("1");
        Mockito.when(trustDistributionParameters.getEntityName()).thenReturn("ENTITY");
        Mockito.when(trustDistributionParameters.getIssuerName()).thenReturn("Issuer");
        Mockito.when(trustDistributionParameters.getCertificateStatus()).thenReturn("status");
        Mockito.when(trustDistributionParameters.getEntityType()).thenReturn("EntityType");

        Mockito.when(trustDistributionParameters.getEntityType()).thenReturn(TDPSEntity.UNKNOWN.getValue());
        trustDistributionParamsValidator.validate(trustDistributionParameters);
    }

    @Test(expected = InvalidCertificateStatusException.class)
    public void testValidateInvalidCertificateStatusException() {

        Mockito.when(trustDistributionParameters.getCertificateSerialId()).thenReturn("1");
        Mockito.when(trustDistributionParameters.getEntityName()).thenReturn("ENTITY");
        Mockito.when(trustDistributionParameters.getIssuerName()).thenReturn("Issuer");
        Mockito.when(trustDistributionParameters.getCertificateStatus()).thenReturn("status");
        Mockito.when(trustDistributionParameters.getEntityType()).thenReturn("EntityType");

        Mockito.when(trustDistributionParameters.getEntityType()).thenReturn(TDPSEntity.ENTITY.getValue());

        Mockito.when(trustDistributionParameters.getCertificateStatus()).thenReturn(TDPSCertificateStatus.UNKNOWN.getValue());

        trustDistributionParamsValidator.validate(trustDistributionParameters);
    }
}
