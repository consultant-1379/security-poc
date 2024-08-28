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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.csr;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CAValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class CAValidatorTest {

    @InjectMocks
    CAValidator cAValidator;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Test(expected = InvalidOperationException.class)
    public void testInvalidOperationException() {
        String name = "CA_ENTITY";
        CAEntity caEntity = new CAEntity();
        CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(name);
        caEntity.setCertificateAuthority(certificateAuthority);

        CAValidationInfo caValidationInfo = new CAValidationInfo();
        caValidationInfo.setCaEntity(caEntity);
        caValidationInfo.setNewKey(true);

        cAValidator.validate(caValidationInfo);
    }

    @Test(expected = InvalidCAException.class)
    public void testInvalidCAException() {
        String name = "CA_ENTITY";
        CAEntity caEntity = new CAEntity();
        CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(name);
        certificateAuthority.setRootCA(true);
        certificateAuthority.setStatus(CAStatus.DELETED);
        caEntity.setCertificateAuthority(certificateAuthority);

        CAValidationInfo caValidationInfo = new CAValidationInfo();
        caValidationInfo.setCaEntity(caEntity);
        caValidationInfo.setNewKey(true);
        cAValidator.validate(caValidationInfo);
    }
}