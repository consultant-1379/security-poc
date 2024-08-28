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
package com.ericsson.oss.itpf.security.pki.manager.local.service.api;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;

import javax.ejb.Local;
import javax.persistence.PersistenceException;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This interface is provided for handling the listener related calls for handling DB persistence related operations for TDPS
 * 
 * @author xdeemin
 *
 */
@EService
@Local
public interface TrustDistributionLocalService {

    /**
     * This method will fetch all the publishedCertificates for both CA and end Entities
     * 
     * @param entityType
     *            type of the entity whether CA_Entity or Entity
     * @return
     * @throws CertificateException
     *             is thrown in case CErtificate is not in proper format
     * @throws IOException
     *             is thorwn in case there is an encoding exception while converting Certificate into a byteArray.
     * @throws PersistenceException
     *             is thrown in case of any internal DB exception
     */
     Map<String, List<Certificate>> getPublishedCertificates(final EntityType entityType) throws CertificateException, IOException, PersistenceException;

    /**
     * This method will update certificateStatus for which TDPS will send acknowledgement status to Manager.
     * 
     * @param tdpsEntityType
     *            is the type of entity which can CA_Entity or Entity.
     * @param entityName
     *            is the name of entity which is present in the PKI system.
     * @param issuerName
     *            is the name of the issuerName who issued certificate to entityName.
     * @param serialNumber
     *            is the serialNumber of the issued certificate.
     * @param tdpsAcknowledgementStatus
     *            is the tdpsAcknowledgmentstatus which can be publish all/singleEntity success/fail or Unpublish all/singleEntity success/fail.
     * @throws CertificateException
     *             is thrown in case CErtificate is not in proper format
     * @throws EntityNotFoundException
     *             is thrown in case entity is not found.
     * @throws IOException
     *             is thrown in case of any encoding exception while converting certificate to byteArray.
     * @throws PersistenceException
     *             is thrown in case of any internal db error.
     */
     void updateCertificateStatus(final EntityType tdpsEntityType, final String entityName, final String issuerName, final String serialNumber, final boolean publishedToTDPS)
            throws CertificateException, EntityNotFoundException, IOException, PersistenceException;
}
