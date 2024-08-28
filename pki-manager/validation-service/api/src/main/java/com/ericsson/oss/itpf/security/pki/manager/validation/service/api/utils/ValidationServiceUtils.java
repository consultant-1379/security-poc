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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ItemType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.builders.ValidateItemBuilder;

/**
 *
 * @author tcsvmeg
 *
 *         This class is used to prepare the validateItem object.
 *
 */
public class ValidationServiceUtils {

    /**
     *
     * @param profileType
     *            Type of profile {@link TrustProfile}, {@link EntityProfile}, {@link CertificateProfile}
     * @param operationType
     *            Operation type whether CREATE/UPDATE
     * @param object
     *            Can be any object
     * @return ValidateItem ValidateItem containing profileType, operationType and any object.
     * @throws InvalidProfileException
     *             This exception is thrown if the given itemType is invalid.
     */
    public ValidateItem generateProfileValidateItem(final ProfileType profileType, final OperationType operationType, final Object object) throws InvalidProfileException {
        ItemType itemType;

        switch (profileType) {
        case CERTIFICATE_PROFILE:
        itemType = ItemType.CERTIFICATE_PROFILE;
            break;
        case ENTITY_PROFILE:
            itemType = ItemType.ENTITY_PROFILE;
            break;
        case TRUST_PROFILE:
            itemType = ItemType.TRUST_PROFILE;
            break;
        default:
            throw new InvalidProfileException("Invalid Item Type! " + profileType.getValue());
        }

        final ValidateItem validateItem = (new ValidateItemBuilder()).setItem(object).setItemType(itemType).setOperationType(operationType).build();

        return validateItem;
    }

    /**
     *
     * @param entityType
     *            Type of Entity {@link CA_ENTITY}, {@link ENTITY}
     * @param operationType
     *            Operation type whether CREATE/UPDATE
     * @param object
     *            Can be any object
     * @return ValidateItem ValidateItem containing EntityType, operationType and any object.
     * @throws InvalidEntityException
     *             This exception is thrown if the given itemType is invalid.
     */
    public ValidateItem generateEntityValidateItem(final EntityType entityType, final OperationType operationType, final Object object) throws InvalidEntityException {
        ItemType itemType;

        switch (entityType) {
        case CA_ENTITY:
            itemType = ItemType.CA_ENTITY;
            break;
        case ENTITY:
            itemType = ItemType.ENTITY;
            break;

        default:
            throw new InvalidEntityException("Invalid Item Type! " + entityType.getValue());
        }

        final ValidateItem validateItem = (new ValidateItemBuilder()).setItem(object).setItemType(itemType).setOperationType(operationType).build();

        return validateItem;
    }

    public ValidateItem generateX509CertificateValidateItem(final ItemType itemType, final OperationType operationType, final Object object, final boolean skipOptionalTests) {

        final ValidateItem validateItem = (new ValidateItemBuilder()).setItem(object).setItemType(itemType).setOperationType(operationType).setSkipOptionalTests(skipOptionalTests).build();
        return validateItem;
    }

    /**
     * This method is used to generate OTP ValidateItem based on given itemType, OperationType, Item and skipOptionalTests. ValidateItem as ( item type : ENTITY_OTP(entityotp) , item: entity,
     * OperationType: VALIDATE, skipOptionalTests : true (It should skip OTP Expiration validation))
     * 
     * @param itemType
     *            Type of Item {@link ENTITY_OTP}
     * @param operationType
     *            Type of Operation VALIDATE
     * @param object
     *            can be any object
     * 
     * @return ValidateItem ValidateItem containing itemType, operationType and any object.
     */
    public ValidateItem generateOtpValidateItem(final ItemType itemType, final OperationType operationType, final Object object) {
        final ValidateItem validateItem = (new ValidateItemBuilder()).setItem(object).setItemType(itemType).setOperationType(operationType).build();
        return validateItem;
    }
}
