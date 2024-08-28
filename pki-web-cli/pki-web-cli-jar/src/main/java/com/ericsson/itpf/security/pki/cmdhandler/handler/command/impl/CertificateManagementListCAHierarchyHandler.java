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

import java.util.ArrayList;
import java.util.List;

import javax.ejb.Local;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandler;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandHandlerInterface;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.CommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * Handler implementation for CertificateManagementListCAHierarchyHandler. This provides service to get CAHierarchy
 *
 * @author xsumnan/xnagcho
 */

@CommandType(PkiCommandType.CACERTIFICATEMANAGEMENTLISTHIERARCHY)
@Local(CommandHandlerInterface.class)
public class CertificateManagementListCAHierarchyHandler implements CommandHandler<PkiPropertyCommand>, CommandHandlerInterface {

    @Inject
    Logger logger;

    @Inject
    CliUtil cliUtil;

    String space = ". . ";

    @Inject
    EServiceRefProxy eServiceRefProxy;

    @Inject
    SystemRecorder systemRecorder;

    PkiCommandResponse commandResponse = null;

    /**
     * Method implementation of CertificateManagementListCAHierarchyHandler. Handles command to get CAHierarchy for CAEntity
     *
     * @param command
     *            - the command
     * @return PkiCommandResponse
     */

    @Override
    public PkiCommandResponse process(final PkiPropertyCommand command) {
        logger.info("CACERTIFICATEMANAGEMENTLISTCAHierarchy command handler");

        final String entityName = command.getValueString(Constants.NAME);
        final boolean isAll = command.hasProperty(Constants.ALL);
        final List<String> messages = new ArrayList<>();
        List<TreeNode<CAEntity>> listHeirarchy = new ArrayList<>();
        try {
            if (isAll) {
                listHeirarchy = eServiceRefProxy.getEntityManagementService().getCAHierarchies();
            } else {
                final TreeNode<CAEntity> caTree = eServiceRefProxy.getEntityManagementService().getCAHierarchyByName(entityName);
                listHeirarchy.add(caTree);
            }

            for (final TreeNode<CAEntity> treenode : listHeirarchy) {
                messages.addAll(buildCAHeirarchyResponse(treenode, Constants.EMPTY_STRING, true));
                messages.add(" ");
            }

        } catch (final EntityNotFoundException entityNotFoundException) {
            logger.debug(PkiErrorCodes.ENTITY_NOT_FOUND, entityNotFoundException);
            return prepareErrorMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND + entityNotFoundException.getMessage());
        } catch (final EntityServiceException entityServiceException) {
            return prepareErrorMessage(ErrorType.ENTITY_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.SERVICE_ERROR + PkiErrorCodes.SUGGEST_SOLUTION + PkiErrorCodes.RETRY, entityServiceException);
        } catch (final SecurityViolationException securityViolationException) {
            logger.error(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION);
            logger.debug(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, securityViolationException);
            return cliUtil.prepareErrorMessage(ErrorType.SECURITY_EXCEPTION.toInt(), PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION, Constants.EMPTY_STRING);
        } catch (final Exception exception) {
            return prepareErrorMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + Constants.EMPTY_STRING + exception.getMessage(), exception);
        }
        systemRecorder.recordSecurityEvent("PKIWebCLI.CACERTIFICATEMANAGEMENTLISTCAHierarchy", "CertificateManagementListCAHierarchyHandler",
                "CA heirarchy listed for CA entity : " + entityName, "Get CA hierarchy for CA entity", ErrorSeverity.INFORMATIONAL, "SUCCESS");
        return buildResponse(messages);
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage, final Throwable cause) {
        logger.error("Error:{} occured while retrieving CAHierarchy {} " ,PkiWebCliException.ERROR_CODE_START_INT + errorCode , cause);
        return PkiCommandResponse.message(errorCode, errorMessage,cause.getMessage());
    }

    private PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorMessage) {
        logger.error("Error: {} occured while retrieving CAHierarchy: {}" , PkiWebCliException.ERROR_CODE_START_INT + errorCode , errorMessage);
        return PkiCommandResponse.message(errorCode, errorMessage,Constants.EMPTY_STRING);
    }

    private PkiMultipleMessageCommandResponse buildResponse(final List<String> messages) {
        final PkiMultipleMessageCommandResponse messageCommandResponse = new PkiMultipleMessageCommandResponse();
        messageCommandResponse.setMessage(messages);
        return messageCommandResponse;
    }

    private List<String> buildCAHeirarchyResponse(final TreeNode<CAEntity> treeNode, final String prefix, final boolean isTail) {
        final CAEntity cadata = treeNode.getData();
        final List<String> messages = new ArrayList<>();
        String s = "";
        s = prefix + (cadata.getCertificateAuthority().isRootCA() ? "" : ("|___ ")) + cadata.getCertificateAuthority().getName();
        messages.add(s);
        for (int i = 0; i < treeNode.getChilds().size() - 1; i++) {
            messages.addAll(buildCAHeirarchyResponse(treeNode.getChilds().get(i), prefix + (isTail ? space : "|" + space), false));
        }
        if (!(treeNode.getChilds().isEmpty())) {
            messages.addAll(buildCAHeirarchyResponse(treeNode.getChilds().get(treeNode.getChilds().size() - 1), prefix + (isTail ? space : "|" + space), true));
        }
        return messages;
    }

}
