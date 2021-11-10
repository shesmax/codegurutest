package service;

import com.amazonaws.services.dynamodbv2.document.Expected;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.PrimaryKey;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.GetItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.amazonaws.services.dynamodbv2.document.utils.ValueMap;
import com.amazonaws.services.dynamodbv2.model.ConditionalCheckFailedException;
import com.amazonaws.services.dynamodbv2.model.ReturnValue;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import exceptions.DbStoreException;
import helpers.DynamoDbHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;

@Singleton
public class DynamoDigitalIdentityStore implements DigitalIdentityStore {
    private final Table table;
    private final Logger logger = LoggerFactory.getLogger(DynamoDigitalIdentityStore.class);
    private static final String STATUS = "status";

    @Inject
    public DynamoDigitalIdentityStore(DynamoDbHelper dynamoDbHelper) {
        this.table = dynamoDbHelper.openTable();
    }

    public boolean save(String tid, String publicKey, String identity) {
        try {
            table.putItem(
                    new Item()
                            .withPrimaryKey("tid", tid, STATUS, 0)
                            .withString("public_key", publicKey)
                            .withString("digital_identity", identity),
                    new Expected("tid").notExist());
            logger.info("Item with tid [{}] has been saved", tid);
            return true;
        } catch (ConditionalCheckFailedException e) {
            logger.info("Item with tid [{}] already exist and unable to save", tid);
            return false;
        } catch (Exception e) {
            logger.error("Unexpected exception during save item with tid: [{}]", tid, e);
            throw new DbStoreException(e.getMessage(), e);
        }
    }

    public Map<String, Object> findById(String tid) {
        try {
            GetItemSpec spec = new GetItemSpec().withPrimaryKey("tid", tid, STATUS, 0);
            logger.info("Searching item with tid [{}]", tid);
            Item item = table.getItem(spec);

            if (item == null) {
                logger.info("Item with tid [{}] not found", tid);
                return Collections.emptyMap();
            }
            return item.asMap();

        } catch (Exception e) {
            logger.error("Unexpected exception during finding tid: {}", tid, e);
            throw new DbStoreException(e.getMessage(), e);
        }
    }

    public boolean update(String tid, String publicKey, String identity) {

        UpdateItemSpec updateItemSpec = new UpdateItemSpec().withPrimaryKey("tid", tid, STATUS, 0)
                .withUpdateExpression("set public_key = :p, digital_identity = :i")
                .withValueMap(
                        new ValueMap()
                                .withString(":p", publicKey)
                                .withString(":i", identity))
                .withReturnValues(ReturnValue.UPDATED_NEW);

        try {
            logger.info("Updating item with tid [{}]", tid);
            table.updateItem(updateItemSpec);
            logger.info("Item with tid [{}] has been updated successful", tid);
        } catch (Exception e) {
            logger.error("Unable to update item with tid [{}]: " + tid, e);
            throw new DbStoreException(e.getMessage(), e);
        }
        return true;
    }

    public boolean delete(String tid) {
        try {
            table.deleteItem(
                    new PrimaryKey("tid", tid, STATUS, 0),
                    new Expected("tid").exists());
            logger.info("Item with tid [{}] deleted", tid);
            return true;
        } catch (ConditionalCheckFailedException e) {
            logger.error("Item with tid [{}] not found to delete", tid);
            return false;
        } catch (Exception e) {
            logger.error("Unexpected exception during deleting tid: [{}]", tid, e);
            throw new DbStoreException(e.getMessage(), e);
        }
    }

    public boolean lock(String tid) throws DbStoreException {
        try {
            table.putItem(new Item().withPrimaryKey("tid", tid, STATUS, 1),
                    new Expected("tid").notExist());
            logger.info("Tid [{}] has been locked", tid);
            return true;
        } catch (ConditionalCheckFailedException e) {
            logger.info("Tid [{}] already locked", tid);
            return false;
        } catch (Exception e) {
            logger.error("Unexpected exception during locking tid: [{}]", tid, e);
            throw new DbStoreException(e.getMessage(), e);
        }
    }

    public boolean unlock(String tid) {
        try {
            table.deleteItem(
                    new PrimaryKey("tid", tid, STATUS, 1),
                    new Expected("tid").exists());
            logger.info("Tid [{}] unlocked", tid);
            return true;
        } catch (ConditionalCheckFailedException e) {
            logger.info("Lock for tid [{}] not found for unlocking", tid);
            return false;
        } catch (Exception e) {
            logger.error("Unexpected exception during unlocking tid: [{}]", tid, e);
            throw new DbStoreException(e.getMessage(), e);
        }
    }
}
