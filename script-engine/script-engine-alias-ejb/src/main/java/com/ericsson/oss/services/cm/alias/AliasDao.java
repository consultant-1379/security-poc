package com.ericsson.oss.services.cm.alias;

import static com.ericsson.oss.services.cli.alias.model.CliAliasVersion.MODEL_VERSION;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import com.ericsson.oss.itpf.datalayer.dps.DataBucket;
import com.ericsson.oss.itpf.datalayer.dps.DataPersistenceService;
import com.ericsson.oss.itpf.datalayer.dps.persistence.PersistenceObject;
import com.ericsson.oss.itpf.datalayer.dps.query.Query;
import com.ericsson.oss.itpf.datalayer.dps.query.Restriction;
import com.ericsson.oss.itpf.datalayer.dps.query.RestrictionBuilder;
import com.ericsson.oss.itpf.datalayer.dps.query.TypeRestrictionBuilder;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.services.cli.alias.model.CliAlias;
import com.ericsson.oss.services.cm.alias.exceptions.CannotFindAliasException;
import com.ericsson.oss.services.cm.alias.exceptions.CannotPersistAliasException;
import org.slf4j.Logger;

/**
 * Alias DAO object to handle all DPS calls for alias commands.
 */
@Stateless
public class AliasDao {
    private static final String EXCEPTION_DURING_ALIAS_SEARCH = "Exception during alias search";
    private static final String EXCEPTION_DURING_ALIAS_PERSISTENCE = "Exception during alias persistence";

    private static final String ALIAS_MODEL_NAMESPACE = "OSS_CLI";
    private static final String ALIAS_MODEL_NAMESPACE_VERSION = MODEL_VERSION;
    private static final String ALIAS_MODEL_TYPE = "CliAlias";
    private static final String ALIAS_NAME_FIELD = "name";

    @EServiceRef
    private DataPersistenceService dps;

    @Inject
    private AliasCache aliasCache;

    @Inject
    private Logger logger;

    /**
     * Creates an Alias in the database, see {@link CliAlias}.
     *
     * @param cliAlias
     *         the {@link CliAlias}
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void createAlias(final CliAlias cliAlias) {
        try {
            final DataBucket liveBucket = dps.getLiveBucket();
            final Map<String, Object> attributes = getCliAliasAttributesForDpsPersistence(cliAlias);
            liveBucket.getPersistenceObjectBuilder()
                      .type(ALIAS_MODEL_TYPE)
                      .namespace(ALIAS_MODEL_NAMESPACE)
                      .version(ALIAS_MODEL_NAMESPACE_VERSION)
                      .addAttributes(attributes)
                      .create();
        } catch (final Exception e) {
            logger.error("createAlias Exception : {}",e.getMessage());
            throw new CannotPersistAliasException(EXCEPTION_DURING_ALIAS_PERSISTENCE);
        }
    }

    /**
     * Searches the Cache by the specified name for the Alias.
     *
     * @param aliasName
     *         the name of the Alias.
     * @return {@link CliAlias}
     */
    public CliAlias getAlias(final String aliasName) {
        return aliasCache.getCliAlias(aliasName);
    }

    /**
     * Searches the Database for the Alias, if found stores it in the CliAliasCache for use later and returns true.
     * This method is called before #getAlias, as the flow is to first check if the command is an Alias and then resolve that Alias.
     *
     * @param aliasName
     *         the name of the Alias.
     * @return true if alias found, false if not.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean isDefinedAlias(final String aliasName) {
        try {
            final Iterator<PersistenceObject> iterator = aliasSearchByName(aliasName);
            if (iterator.hasNext()) {
                final CliAlias cliAlias = getCliAliasFromPersistenceObject(iterator);
                aliasCache.addCliAlias(cliAlias);
                return true;
            }
        } catch (final Exception e) {
            logger.error("isDefinedAlias Exception :  {}",e.getMessage());
            throw new CannotFindAliasException(EXCEPTION_DURING_ALIAS_SEARCH);
        }
        return false;
    }

    /*
     * P R I V A T E  - M E T H O D S
     */

    private Iterator<PersistenceObject> aliasSearchByName(final String aliasName) {
        final DataBucket liveBucket = dps.getLiveBucket();
        final Query<? extends RestrictionBuilder> aliasQuery = dps.getQueryBuilder().createTypeQuery(ALIAS_MODEL_NAMESPACE, ALIAS_MODEL_TYPE);
        applyQueryRestrictionsForAlias(aliasName, aliasQuery);
        return liveBucket.getQueryExecutor().execute(aliasQuery);
    }

    private void applyQueryRestrictionsForAlias(final String aliasName, final Query<? extends RestrictionBuilder> aliasQuery) {
        final TypeRestrictionBuilder restrictionBuilder = (TypeRestrictionBuilder) aliasQuery.getRestrictionBuilder();
        final Restriction[] restrictions = new Restriction[] {
                restrictionBuilder.equalTo(ALIAS_NAME_FIELD, aliasName)
        };
        aliasQuery.setRestriction(restrictionBuilder.allOf(restrictions));
    }

    private CliAlias getCliAliasFromPersistenceObject(final Iterator<PersistenceObject> iterator) {
        final CliAlias cliAlias = new CliAlias();
        final PersistenceObject aliasPersistenceObject = iterator.next();
        final Map<String, Object> aliasAttributes = aliasPersistenceObject.getAllAttributes();
        try {
            for (final Field field : CliAlias.class.getFields()) {
                field.set(cliAlias, aliasAttributes.get(field.getName()));
            }
        } catch (final IllegalAccessException e) {
            // Cannot happen because we are iterating over its own fields
        }
        return cliAlias;
    }

    private Map<String, Object> getCliAliasAttributesForDpsPersistence(final CliAlias cliAlias) {
        final Map<String, Object> attributes = new HashMap<>();
        try {
            for (final Field field : CliAlias.class.getFields()) {
                attributes.put(field.getName(), field.get(cliAlias));
            }
        } catch (final IllegalArgumentException | IllegalAccessException e) {
            // Cannot happen because we are iterating over its own fields
        }
        return attributes;
    }
}
