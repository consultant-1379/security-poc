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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.builder;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.builder.TDPSErrorInfoBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSErrorInfo;

/**
 * 
 * @author tcsasma
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class TDPSErrorInfoBuilderTest {

    @InjectMocks
    TDPSErrorInfoBuilder tdpsErrorInfoBuilder;

    @Test
    public void testErrorMessage() {
        tdpsErrorInfoBuilder.errorMessage("Error Message");
    }

    @Test
    public void testBuild() {
        TDPSErrorInfo tdpsErrorInfo = new TDPSErrorInfo();
        tdpsErrorInfo = tdpsErrorInfoBuilder.build();
        Assert.assertNotNull(tdpsErrorInfo);
    }

}
