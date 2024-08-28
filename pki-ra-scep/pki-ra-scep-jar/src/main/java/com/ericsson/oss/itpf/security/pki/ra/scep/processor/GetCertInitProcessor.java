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
package com.ericsson.oss.itpf.security.pki.ra.scep.processor;

import java.util.HashMap;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.BadRequestException;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity.Pkcs7ScepRequestEntity;

/**
 * This class has methods to check the associated PKCSReq transaction details in the DB by fetching the record using transaction Id, subject name and issuer name.
 *
 * @author xtelsow
 */
public class GetCertInitProcessor {
    @Inject
    private Logger logger;
    @Inject
    private PersistenceHandler peristanceHandler;
    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method retrieves the Pkcs7ScepRequestEntity record from the database to process the GetCertInitial request.
     *
     * @param pkcs7ScepRequestData
     *            contains SCEP request data.
     * @return Pkcs7ScepRequestEntity is the initial PKCSReq record.
     *
     * @throws BadRequestException
     *             BadRequestException will be thrown when PKCSReq record is not found in database
     */
    public Pkcs7ScepRequestEntity processRequest(final Pkcs7ScepRequestData pkcs7ScepRequestData) throws BadRequestException {
        logger.debug("In processRequest method in GetCertInitProcessor class");
        final Pkcs7ScepRequestEntity pkcs7ScepRequestEntity = getPkcs7ScepRequestEntity(pkcs7ScepRequestData);
        logger.debug("End of processRequest method in GetCertInitProcessor class");
        return pkcs7ScepRequestEntity;
    }

    /**
     * This method fetches the record from database depending on the values being passed.
     *
     * @param pkcs7ScepRequestData
     *            contains SCEP request data.
     * @return Pkcs7ScepRequestEntity is the Entity object fetched from database for the given search criteria.
     * @throws BadRequestException
     *             BadRequestException will be thrown when PKCSReq record is not found in database
     * 
     *
     */
    private Pkcs7ScepRequestEntity getPkcs7ScepRequestEntity(final Pkcs7ScepRequestData pkcs7ScepRequestData) throws BadRequestException {
        final HashMap<String, Object> parameters = new HashMap<>();
        parameters.put("transactionId", pkcs7ScepRequestData.getTransactionId());
        if (pkcs7ScepRequestData.getIssuerAndSubjectName() != null && pkcs7ScepRequestData.getIssuerAndSubjectName().getIssuerName() != null
                && pkcs7ScepRequestData.getIssuerAndSubjectName().getSubjectName() != null) {
            parameters.put("subjectDN", pkcs7ScepRequestData.getIssuerAndSubjectName().getSubjectName());
            parameters.put("issuerDN", pkcs7ScepRequestData.getIssuerAndSubjectName().getIssuerName());

        }

        final List<Pkcs7ScepRequestEntity> requestResponseEntitiesList = peristanceHandler.searchEntitiesByAttributes(Pkcs7ScepRequestEntity.class, parameters);
        if (!requestResponseEntitiesList.isEmpty()) {
            return requestResponseEntitiesList.get(0);
        } else {
            logger.error("No associated PKCSReq is found in the data base in PKCS7 Request with the Transaction Id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                    + pkcs7ScepRequestData.getEndEntityName());
            systemRecorder.recordError(
                    "PKI_RA_SCEP.REQUEST_NOT_FOUND_IN_DATABASE",
                    ErrorSeverity.ERROR,
                    "GetCertInitProcessor",
                    "SCEP Enrollement for End Entity",
                    "No associated Certificate Request found in the data base with transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                            + pkcs7ScepRequestData.getEndEntityName());
            throw new BadRequestException(ErrorMessages.NO_ASS0CIATED_PKCSREQ);
        }
    }

}