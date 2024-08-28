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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils;

import javax.ejb.EJB;

import javax.naming.InvalidNameException;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.PKIMessageUtil;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.EntityManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

/**
 * This class is used for getting the entity information.
 * 
 * @author tcschdy
 *
 */
public class EntityHandlerUtility {

    @EJB
    EntityManagementLocalService entityManagementLocalService;

    /**
     * This method is used to get the entity name based on the subject DN provided in the CMP Request Message
     * 
     * @param pKIRequestMessage
     *            the request message from which the subject details are extracted.
     * @return entity name for which the certificate need to be generated
     * @throws AlgorithmNotFoundException
     *             thrown when the specified algorithm is not supported
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidNameException
     *             Thrown when subject DN is in improper format.
     */
    public String getEntityName(final RequestMessage pKIRequestMessage) throws AlgorithmNotFoundException, EntityNotFoundException, EntityServiceException, InvalidNameException {
        final String subjectDN = PKIMessageUtil.getSubjectDNfromPKIMessage(pKIRequestMessage.getPKIMessage());
        final String issuerDN = pKIRequestMessage.getRecipientName();
        final Entity entity = entityManagementLocalService.getEntity(subjectDN, issuerDN);
        return entity.getEntityInfo().getName();
    }

}