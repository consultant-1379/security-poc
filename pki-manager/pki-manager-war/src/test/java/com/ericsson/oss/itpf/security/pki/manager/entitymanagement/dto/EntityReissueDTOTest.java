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

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfilesDTO;

@RunWith(MockitoJUnitRunner.class)
public class EntityReissueDTOTest {

    EntityReissueDTO entityReissueDTO;
    EntityReissueDTO expectedEntityReissueDTO;

    @Before
    public void setUP() {
        entityReissueDTO = getEntityReissueDTO();
        expectedEntityReissueDTO = getEntityReissueDTO();

    }

    @Test
    public void testEqualsPositive() {

        entityReissueDTO.hashCode();
        entityReissueDTO.toString();

        assertTrue(entityReissueDTO.equals(entityReissueDTO));
        entityReissueDTO.equals(null);

        assertFalse(entityReissueDTO.equals(new ProfilesDTO()));
    }

    @Test
    public void testEqualsNegative() {

        expectedEntityReissueDTO.setChain(true);
        entityReissueDTO.equals(expectedEntityReissueDTO);
        expectedEntityReissueDTO.setChain(false);
        expectedEntityReissueDTO.getFormat();
        expectedEntityReissueDTO.setFormat(KeyStoreType.PEM);
        assertFalse(expectedEntityReissueDTO.isChain());
        assertFalse(entityReissueDTO.equals(expectedEntityReissueDTO));
        expectedEntityReissueDTO.setFormat(KeyStoreType.JKS);
        expectedEntityReissueDTO.setName("Tes");
        entityReissueDTO.equals(expectedEntityReissueDTO);
        expectedEntityReissueDTO.setName(entityReissueDTO.getName());
        entityReissueDTO.setName(null);

        assertFalse(entityReissueDTO.equals(expectedEntityReissueDTO));
        entityReissueDTO.setName("Entity");
    }

    @Test
    public void testNotEqualsNoPassword() {

        entityReissueDTO.setPassword("test");

        assertFalse(entityReissueDTO.equals(expectedEntityReissueDTO));
        entityReissueDTO.setPassword(expectedEntityReissueDTO.getPassword());
        entityReissueDTO.setPassword(null);

        assertFalse(entityReissueDTO.equals(expectedEntityReissueDTO));

        entityReissueDTO.setPassword(expectedEntityReissueDTO.getPassword());

    }

    public EntityReissueDTO getEntityReissueDTO() {
        final EntityReissueDTO entityReissueDTO = new EntityReissueDTO();
        entityReissueDTO.setChain(false);
        entityReissueDTO.setFormat(KeyStoreType.JKS);
        entityReissueDTO.setPassword("secure");
        entityReissueDTO.setName("Entity");
        return entityReissueDTO;
    }
}
