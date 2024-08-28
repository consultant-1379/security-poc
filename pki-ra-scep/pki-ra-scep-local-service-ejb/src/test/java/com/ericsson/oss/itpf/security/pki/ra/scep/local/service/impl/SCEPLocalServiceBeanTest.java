/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.local.service.impl;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.scep.model.ScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.PersistenceHandler;

@RunWith(MockitoJUnitRunner.class)
public class SCEPLocalServiceBeanTest {

    @InjectMocks
    SCEPLocalServiceBean scepLocalServiceBean;

    @Mock
    Logger logger;

    @Mock
    PersistenceHandler persistenceHandler;

    @Mock
    ScepResponse scepResponse;

    @Test
    public void updateSCEPResponseStatusTest() {
        scepLocalServiceBean.updateSCEPResponseStatus(scepResponse);
    }
}
