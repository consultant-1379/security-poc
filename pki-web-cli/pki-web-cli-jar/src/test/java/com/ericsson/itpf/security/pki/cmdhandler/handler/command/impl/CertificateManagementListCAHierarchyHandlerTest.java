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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementListCAHierarchyHandlerTest {
    @InjectMocks
    CertificateManagementListCAHierarchyHandler certificateManagementListCaHierarchyHandler;

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliUtil;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementListCAHierarchyHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;
    private final Map<String, Object> properties = new HashMap<String, Object>();

    private final List<TreeNode<CAEntity>> listHeirarchy = new ArrayList<TreeNode<CAEntity>>();

    private final TreeNode<CAEntity> treeNode = new TreeNode<CAEntity>();

    private final CAEntity caEntity = new CAEntity();

    @Before
    public void setUp() throws Exception {
        properties.put("command", "CACERTIFICATEMANAGEMENTLIST");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CACERTIFICATEMANAGEMENTLIST);
        properties.put("name", "caName");

        caEntity.setCertificateAuthority(new CertificateAuthority());
        treeNode.setData(caEntity);
        listHeirarchy.add(treeNode);
        Mockito.when(eServiceRefProxy.getEntityManagementService()).thenReturn(entityManagementService);
    }

    @Test
    public void testProcessCommand() {
        properties.put("all", "caAll");
        command.setProperties(properties);
        Mockito.when(entityManagementService.getCAHierarchies()).thenReturn(listHeirarchy);
        final PkiCommandResponse pkiCommandResponse = certificateManagementListCaHierarchyHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE_MULTIPLE_VALUE);
    }

    @Test
    public void testProcessCommandByName() {
        command.setProperties(properties);
        Mockito.when(entityManagementService.getCAHierarchyByName(Mockito.anyString())).thenReturn(treeNode);
        final PkiCommandResponse pkiCommandResponse = certificateManagementListCaHierarchyHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE_MULTIPLE_VALUE);
    }

    @Test
    @Ignore
    public void testProcessCommandEntityNotFoundException() {
        properties.put("all", "caAll");
        command.setProperties(properties);
        Mockito.when(entityManagementService.getCAHierarchies()).thenThrow(EntityNotFoundException.class);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListCaHierarchyHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11099 This is an unexpected system error, please check the error log for more details."));
    }

    @Test
    public void testProcessCommandException() {
        properties.put("all", "caAll");
        command.setProperties(properties);
        Mockito.when(entityManagementService.getCAHierarchies()).thenThrow(Exception.class);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListCaHierarchyHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR)));
    }

    @Test
    public void testProcessCommandEntityServiceException() {
        properties.put("all", "caAll");
        command.setProperties(properties);
        Mockito.when(entityManagementService.getCAHierarchies()).thenThrow(EntityServiceException.class);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListCaHierarchyHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));
    }

    @Test
    public void testProcessCommand_SecurityViolationException() {
        properties.put("all", "caAll");
        command.setProperties(properties);
        Mockito.when(entityManagementService.getCAHierarchies()).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        certificateManagementListCaHierarchyHandler.process(command);
    }
}
