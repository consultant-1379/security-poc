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
package com.ericsson.oss.itpf.security.pki.manager.rest.helpers;

import java.util.ArrayList;

import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.rest.mappers.CertificateRevocationInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.LoadErrorProperties;

/**
 * This class prepares the RevocationStatusDTO's list by using EntityRevocationInfoDTO or CertificateRevocationInfoDTO's list and EntityType
 *
 * @author xnarsir
 *
 */
public class RevocationRestResourceHelper {

    @Inject
    private Logger logger;
    @Inject
    PKIManagerEServiceProxy pkiManagerEServiceProxy;
    @Inject
    private CertificateRevocationInfoMapper certificateRevokeInfoMapper;

    @Inject
    private LoadErrorProperties loadErrorProperties;

    /**
     * This method is used to prepare the RevocationStatusDTO's list from the EntityRevocationInfoDTO
     *
     * @param entityRevocationInfoDTO
     *            It consists of entityName and revocationReason
     * @param entityType
     *            represents the type of an entity
     * @return List of RevocationStatusDTO objects, each RevocationStatusDTO object consists of serialNumber,issuer,subject and message.
     */

    public List<RevocationStatusDTO> getRevokeStatusDTOList(final EntityRevocationInfoDTO entityRevocationInfoDTO, final EntityType entityType) {
        logger.debug("getRevokeStatusDTOList method in RevocationStatusInfoHelper class");
        final List<RevocationStatusDTO> revocationStatusDTOList = new ArrayList<RevocationStatusDTO>();
        final RevocationStatusDTO revocationStatusDTO = new RevocationStatusDTO();
        final String message = "All the Entity Certificates in a state compatible with the revocation have been revoked.";
        try {
            if (entityType == EntityType.CA_ENTITY) {
                pkiManagerEServiceProxy.getRevocationService().revokeCAEntityCertificates(entityRevocationInfoDTO.getEntityName(),
                        entityRevocationInfoDTO.getRevocationReason(), null);
            } else {
                pkiManagerEServiceProxy.getRevocationService().revokeEntityCertificates(entityRevocationInfoDTO.getEntityName(),
                        entityRevocationInfoDTO.getRevocationReason(), null);
            }
            revocationStatusDTO.setStatus(Status.OK.getStatusCode());
            revocationStatusDTO.setCode(loadErrorProperties.getRevocationErrorCode(message));
            revocationStatusDTO.setMessage(message);

        } catch (final EntityNotFoundException revocationException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_REVOCATION_ENTITY + entityRevocationInfoDTO.getEntityName(), revocationException);
            logger.error("Entity {} certificate revocation failed due to {}" + entityRevocationInfoDTO.getEntityName(), revocationException.getMessage());
            revocationStatusDTO.setStatus(Status.BAD_REQUEST.getStatusCode());
            revocationStatusDTO.setCode(loadErrorProperties.getRevocationErrorCode(revocationException.getMessage()));
            revocationStatusDTO.setMessage(revocationException.getMessage());
        } catch (final CertificateNotFoundException revocationException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_REVOCATION_ENTITY + entityRevocationInfoDTO.getEntityName(), revocationException);
            logger.error("Entity {} certificate revocation failed due to {}" + entityRevocationInfoDTO.getEntityName(), revocationException.getMessage());
            revocationStatusDTO.setStatus(Status.BAD_REQUEST.getStatusCode());
            revocationStatusDTO.setCode(loadErrorProperties.getRevocationErrorCode(revocationException.getMessage()));
            revocationStatusDTO.setMessage(revocationException.getMessage());
        } catch (final ExpiredCertificateException revocationException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_REVOCATION_ENTITY + entityRevocationInfoDTO.getEntityName(), revocationException);
            logger.error("Entity {} certificate revocation failed due to {}" + entityRevocationInfoDTO.getEntityName(), revocationException.getMessage());
            revocationStatusDTO.setStatus(Status.BAD_REQUEST.getStatusCode());
            revocationStatusDTO.setCode(loadErrorProperties.getRevocationErrorCode(revocationException.getMessage()));
            revocationStatusDTO.setMessage(revocationException.getMessage());
        } catch (final RevokedCertificateException revocationException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_REVOCATION_ENTITY + entityRevocationInfoDTO.getEntityName(), revocationException);
            logger.error("Entity {} certificate revocation failed due to {}" + entityRevocationInfoDTO.getEntityName(), revocationException.getMessage());
            revocationStatusDTO.setStatus(Status.BAD_REQUEST.getStatusCode());
            revocationStatusDTO.setCode(loadErrorProperties.getRevocationErrorCode(revocationException.getMessage()));
            revocationStatusDTO.setMessage(revocationException.getMessage());
        } catch (final RevocationServiceException revocationException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_REVOCATION_ENTITY + entityRevocationInfoDTO.getEntityName(), revocationException);
            logger.error("Entity {} certificate revocation failed due to {}" + entityRevocationInfoDTO.getEntityName(), revocationException.getMessage());
            revocationStatusDTO.setStatus(Status.INTERNAL_SERVER_ERROR.getStatusCode());
            revocationStatusDTO.setCode(loadErrorProperties.getRevocationErrorCode(revocationException.getMessage()));
            revocationStatusDTO.setMessage(revocationException.getMessage());
        } catch (final RootCertificateRevocationException revocationException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_REVOCATION_ENTITY, revocationException);
            logger.error("Entity {} certificate revocation failed due to {}" + entityRevocationInfoDTO.getEntityName(), revocationException.getMessage());
            revocationStatusDTO.setStatus(Status.BAD_REQUEST.getStatusCode());
            revocationStatusDTO.setCode(loadErrorProperties.getRevocationErrorCode(revocationException.getMessage()));
            revocationStatusDTO.setMessage(revocationException.getMessage());
        } catch (final SecurityViolationException securityViolationException) {
            logger.debug("Security Violation occured", securityViolationException);
            logger.error("Entity {} certificate revocation failed due to {}" + entityRevocationInfoDTO.getEntityName(), securityViolationException.getMessage());
            revocationStatusDTO.setStatus(Status.BAD_REQUEST.getStatusCode());
            revocationStatusDTO.setCode(loadErrorProperties.getRevocationErrorCode(securityViolationException.getMessage()));
            revocationStatusDTO.setMessage(loadErrorProperties.getMessage(securityViolationException.getMessage()));
        } catch (final Exception revocationException) {
            logger.error("Entity {} certificate revocation failed due to {}" + entityRevocationInfoDTO.getEntityName(), revocationException.getMessage());
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_REVOCATION_ENTITY, entityRevocationInfoDTO.getEntityName(), revocationException);
            revocationStatusDTO.setStatus(Status.BAD_REQUEST.getStatusCode());
            revocationStatusDTO.setCode(loadErrorProperties.getRevocationErrorCode(revocationException.getMessage()));
            revocationStatusDTO.setMessage(revocationException.getMessage());
        }

        revocationStatusDTOList.add(revocationStatusDTO);
        logger.debug("End of getRevokeStatusDTOList method in RevocationStatusInfoHelper class");
        return revocationStatusDTOList;
    }

    /**
     * This method is used to prepare the RevocationStatusDTO's list from the CertificateRevocationInfoDTO's list
     *
     * @param certificateRevocationInfoDTOs
     *            It has serialNumber, subject, issuer and revocation reason
     * @param entityType
     *            represents the type of an entity
     * @return List of RevocationStatusDTO objects, each RevocationStatusDTO object consists of serialNumber,issuer,subject and message.
     */
    public List<RevocationStatusDTO> getRevokeStatusDTOList(final List<CertificateRevocationInfoDTO> certificateRevocationInfoDTOs, final EntityType entityType) {
        logger.debug("getRevokeStatusDTOList method in RevocationStatusInfoHelper class");
        final List<RevocationStatusDTO> revocationStatusDTOList = new ArrayList<RevocationStatusDTO>();
        for (final CertificateRevocationInfoDTO certificateRevocationInfoDTO : certificateRevocationInfoDTOs) {
            final DNBasedCertificateIdentifier dnBasedCertificateIdentifier = certificateRevokeInfoMapper.getDnBasedCertificateIdentifier(certificateRevocationInfoDTO);

            try {

                /*
                 * TODO Since there are no separate methods for revoking CA and Entity certtificates, Using same method for both the cases. But this separation need to be handled after RBAC is
                 * finalized.
                 */
                pkiManagerEServiceProxy.getRevocationService().revokeCertificateByDN(dnBasedCertificateIdentifier,
                            certificateRevocationInfoDTO.getRevocationReason(), null);
                final String message = "Certificate has been revoked.";
                revocationStatusDTOList
                        .add(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevocationInfoDTO, message, Status.OK.getStatusCode(), loadErrorProperties.getRevocationErrorCode(message)));

            } catch (final EntityNotFoundException revocationException) {
                logger.debug("Unable to revoke the certificate: ", revocationException);
                logger.error("Unable to revoke the certificate: " + revocationException.getMessage());
                revocationStatusDTOList.add(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevocationInfoDTO, revocationException.getMessage(), Status.BAD_REQUEST.getStatusCode(),
                        loadErrorProperties.getRevocationErrorCode(revocationException.getMessage())));
            } catch (final CertificateNotFoundException revocationException) {
                logger.debug("Unable to revoke the certificate: ", revocationException);
                logger.error("Unable to revoke the certificate: " + revocationException.getMessage());
                revocationStatusDTOList.add(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevocationInfoDTO, revocationException.getMessage(), Status.BAD_REQUEST.getStatusCode(),
                        loadErrorProperties.getRevocationErrorCode(revocationException.getMessage())));
            } catch (final ExpiredCertificateException revocationException) {
                logger.debug("Unable to revoke the certificate: ", revocationException);
                logger.error("Unable to revoke the certificate: " + revocationException.getMessage());
                revocationStatusDTOList.add(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevocationInfoDTO, revocationException.getMessage(), Status.BAD_REQUEST.getStatusCode(),
                        loadErrorProperties.getRevocationErrorCode(revocationException.getMessage())));
            } catch (final RevokedCertificateException revocationException) {
                logger.debug("Unable to revoke the certificate: ", revocationException);
                logger.error("Unable to revoke the certificate: " + revocationException.getMessage());
                revocationStatusDTOList.add(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevocationInfoDTO, revocationException.getMessage(), Status.BAD_REQUEST.getStatusCode(),
                        loadErrorProperties.getRevocationErrorCode(revocationException.getMessage())));
            } catch (final RevocationServiceException revocationException) {
                logger.debug("Unable to revoke the certificate: ", revocationException);
                logger.error("Unable to revoke the certificate: " + revocationException.getMessage());
                revocationStatusDTOList.add(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevocationInfoDTO, revocationException.getMessage(),
                        Status.INTERNAL_SERVER_ERROR.getStatusCode(), loadErrorProperties.getRevocationErrorCode(revocationException.getMessage())));
            } catch (final RootCertificateRevocationException revocationException) {
                logger.debug("Unable to revoke the certificate: ", revocationException);
                logger.error("Unable to revoke the certificate: " + revocationException.getMessage());
                revocationStatusDTOList.add(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevocationInfoDTO, revocationException.getMessage(), Status.BAD_REQUEST.getStatusCode(),
                        loadErrorProperties.getRevocationErrorCode(revocationException.getMessage())));
            } catch (final IssuerNotFoundException revocationException) {
                logger.debug("Unable to revoke the certificate: ", revocationException);
                logger.error("Unable to revoke the certificate: " + revocationException.getMessage());
                revocationStatusDTOList.add(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevocationInfoDTO, revocationException.getMessage(), Status.BAD_REQUEST.getStatusCode(),
                        loadErrorProperties.getRevocationErrorCode(revocationException.getMessage())));
            } catch (final SecurityViolationException securityViolationException) {
                logger.debug("Unable to revoke the certificate: ", securityViolationException);
                logger.error("Unable to revoke the certificate: " + securityViolationException.getMessage());
                revocationStatusDTOList.add(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevocationInfoDTO, loadErrorProperties.getMessage(securityViolationException.getMessage()),
                        Status.BAD_REQUEST.getStatusCode(), loadErrorProperties.getRevocationErrorCode(securityViolationException.getMessage())));
            } catch (final Exception revocationException) {
                logger.error("Unable to revoke the certificate: " + revocationException.getMessage());
                logger.debug("Unable to revoke the certificate: ", revocationException);
                revocationStatusDTOList.add(certificateRevokeInfoMapper.getRevocationStatusDTO(certificateRevocationInfoDTO, revocationException.getMessage(), Status.BAD_REQUEST.getStatusCode(),
                        loadErrorProperties.getRevocationErrorCode(revocationException.getMessage())));
            }
        }
        logger.debug("End of getRevokeStatusDTOList method in RevocationStatusInfoHelper class");
        return revocationStatusDTOList;
    }
}
