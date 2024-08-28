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
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfilesDTO;

/**
 * This class will test CAReissueDTOTest
 * 
 * 
 * @author tcsrav
 * 
 */

@RunWith(MockitoJUnitRunner.class)
public class CAReissueDTOTest {

    CAReissueDTO caReissueDTO;

    @Before
    public void setup() {
        caReissueDTO = getCAReissueDTO();

    }

    /**
     * Method to test Positive scenario
     * 
     */

    @Test
    public void testDtoEquals() {

        caReissueDTO.hashCode();
        assertTrue(caReissueDTO.equals(caReissueDTO));

        assertFalse(caReissueDTO.equals(null));
        assertFalse(caReissueDTO.equals(new ProfilesDTO()));

    }

    private CAReissueDTO getCAReissueDTO() {
        final CAReissueDTO caReissueDTO = new CAReissueDTO();
        caReissueDTO.setName("ENMRootCA");
        caReissueDTO.setReIssueType(ReIssueType.CA);
        caReissueDTO.setRekey(false);
        return caReissueDTO;
    }

}
