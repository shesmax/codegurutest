package controllers;

import com.fasterxml.jackson.databind.JsonNode;
import exceptions.DbStoreException;
import helpers.CallContext;
import helpers.HsmSigner;
import helpers.KeyRoutines;
import org.slf4j.Logger;
import org.slf4j.MDC;
import play.data.validation.ValidationError;
import play.libs.Json;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;

import com.google.inject.Inject;
import com.typesafe.config.Config;

import org.slf4j.LoggerFactory;

import java.io.IOException;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

import java.text.ParseException;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;

import models.DigitalIdentityModel;
import models.DigitalIdentityLockModel;

import representations.*;

import helpers.MessageValidatorService;

import com.hilti.cloud.errors.exceptions.*;
import static com.hilti.cloud.errors.constant.Constants.TRANSACTION_HEADER;
import com.hilti.cloud.errors.constant.ErrorCode;
import service.DigitalIdentityStore;

import static com.hilti.cloud.errors.constant.ErrorCode.*;

public class ApplicationController extends Controller
{
    private final String patternJws;

    private static final String NOT_FOUND_DB = " does not exist in the database";
    private static final String THE_FIELD_IS_MISSING_IN_PAYLOAD = "the field is missing in the payload";

    private final MessageValidatorService messageValidatorService;

    private static final Logger logger = LoggerFactory.getLogger(ApplicationController.class);
    private final String serviceName;
    private final HsmSigner hsmSigner;
    private final DigitalIdentityStore digitalIdentityStore;

    @Inject
    public ApplicationController(final Config config,
                                 final MessageValidatorService messageValidatorService,
                                 final HsmSigner hsmSigner,
                                 final DigitalIdentityStore digitalIdentityStore)
    {
        patternJws = config.getString("jws.validation_pattern");
        serviceName = config.getString("app.name") + ":" + config.getString("app.version");
        this.messageValidatorService = messageValidatorService;
        this.digitalIdentityStore = digitalIdentityStore;
        this.hsmSigner = hsmSigner;
    }

    //
    // GET /
    //
    public Result info()
    {
        return ok(String.format("%s started", serviceName));
    }

    //
    // POST /signing-requests
    //
    public CompletionStage<Result> createDigitalIdentity(Http.Request request)
    {
        final CallContext callContext = initRequestProcessing(request);
        return CompletableFuture.supplyAsync(() -> {
            callContext.setRequest(request);
            lockTID(callContext);
            findDigitalIdentityRecord(callContext);
            if (callContext.isDigitalIdentityRecordFound())
                // It is not allowed to POST an identity more than once. If you want to update
                // an existing identity please delete the old one and then POST the updated value
                // or use the PUT operation.
                throw new CloudBasicException(CONFLICT_RESOURCE_EXISTS, callContext.getTid() + " exists already");
            return callContext;
        })

        .thenCompose(ctx -> messageValidatorService.postKey(callContext))

        .thenApply(ctx -> {
            logger.info("The key was created in SAP");
            createDigitalIdentityRecord(callContext);
            createServiceResponseAsDigitalIdentity(callContext, true);
            finishRequestProcessing(callContext);
            return callContext.getResult();
        })

        .exceptionally(exc -> handleException(exc, callContext));
    }

    //
    // PUT /signing-requests
    //
    public CompletionStage<Result> updatePublicKey(Http.Request request)
    {
        CallContext callContext = initRequestProcessing(request);

        return
        addAsyncClosure(
            CompletableFuture.supplyAsync(() -> {
                callContext.setRequest(request);
                lockTID(callContext);
                findDigitalIdentityRecord(callContext);
                if (!callContext.isDigitalIdentityRecordFound())
                    throw new CloudBasicException(NOT_FOUND_DATA_FROM_RESOURCE, callContext.getTid() + NOT_FOUND_DB);
                return callContext;
            })

            .thenCompose(ctx -> messageValidatorService.deleteKey(callContext, false))
            .thenCompose(ctx -> messageValidatorService.postKey(callContext))

            .thenApply(ctx -> {
                logger.info("The key was deleted and recreated in sap");
                updateDigitalIdentityRecord(callContext);
                createServiceResponseAsDigitalIdentity(callContext, false);
                return callContext;
            }), callContext
        );
    }

    //
    // GET /thing-identity/:id
    //
    public CompletionStage<Result> getDigitalIdentity(String toolID, Http.Request request)
    {
        CallContext callContext = initRequestProcessing(request);

        return addAsyncClosure(
            CompletableFuture.supplyAsync(() -> {
                callContext.setRequest(toolID);
                findDigitalIdentityRecord(callContext);
                if (!callContext.isDigitalIdentityRecordFound())
                    throw new CloudBasicException(NOT_FOUND_DATA_FROM_RESOURCE, toolID + NOT_FOUND_DB);
                return callContext;
            })

            .thenCompose(ctx -> messageValidatorService.getKey(callContext))

            .thenApply(ctx -> {
                String pemInSAP = callContext.getWsResponse().asJson().get("pem").asText();
                if (!pemInSAP.equals(callContext.getDigitalIdentityRecord().getPublicKey()))
                    throw new CloudBasicException(NOT_FOUND_DATA_FROM_RESOURCE,
                            toolID + ": public keys in service database are not in sync");
                logger.info("The keys in the database and in SAP are in sync");
                createServiceResponseAsDigitalIdentity(callContext, false);
                return callContext;
            }), callContext
        );
    }

    //
    // DELETE /signing-requests/:id
    //
    public CompletionStage<Result> deleteDigitalIdentity(String toolID, Http.Request request)
    {
        CallContext callContext = initRequestProcessing(request);

        return
        addAsyncClosure(
            CompletableFuture.supplyAsync(() -> {
                callContext.setRequest(toolID);
                lockTID(callContext);
                findDigitalIdentityRecord(callContext);
                if (!callContext.isDigitalIdentityRecordFound())
                    throw new CloudBasicException(NOT_FOUND_DATA_FROM_RESOURCE, callContext.getTid() + NOT_FOUND_DB);
                if (callContext.isDigitalIdentityRecordFound()) {
                    callContext.getDigitalIdentityRecord().delete();
                    logger.info("The record was deleted from the database");
                }
                return callContext;
            })

            .thenCompose(ctx -> messageValidatorService.deleteKey(callContext, true))

            .thenApply(ctx -> {
                createServiceResponseAsDigitalIdentity(callContext, false);
                return callContext;
            }), callContext
        );
    }

    //
    // POST /validate-signature
    //
    public CompletionStage<Result> validateSignature(Http.Request request)
    {
        CallContext callContext = initRequestProcessing(request);

        return addAsyncClosure(
            CompletableFuture.supplyAsync(() -> {
                IoTDataMessage msg = parseValidateSignatureRequest(request);
                IoTDecodedDataMessage decodedMessage = new IoTDecodedDataMessage(msg.getCapabilityAlternateId(),
                        msg.getSensorAlternateId());

                for (IoTMeasure measure : msg.getMeasures()) {
                    String signerAlternateId = measure.getSignerAlternateId();
                    callContext.setRequest(signerAlternateId);
                    findDigitalIdentityRecord(callContext);
                    if (!callContext.isDigitalIdentityRecordFound())
                        throw new CloudBasicException(NOT_FOUND_DATA_FROM_RESOURCE, signerAlternateId + NOT_FOUND_DB);
                    decodedMessage.setMeasures(decodeMeasure(measure, callContext.getDigitalIdentityRecord()));
                }

                logger.info("Message verified");
                callContext.setResult(ok(Json.toJson(decodedMessage)));
                return callContext;
            }), callContext
        );
    }

    //
    // Internally-used helper methods
    //

    private CompletionStage<Result> addAsyncClosure(CompletionStage<CallContext> previousSteps, CallContext callContext)
    {
        return previousSteps
                .thenApply(ctx -> {
                    finishRequestProcessing(callContext);
                    return callContext.getResult();
                })
                .exceptionally(exception -> handleException(exception, callContext));
    }

    private String constructDigitalIdentity(DigitalIdentityProcessingRequest request) throws CloudBasicException
    {
        try {
            // extract tool's (=device) public key as a base64-encoded string
            String toolPubkey = KeyRoutines.extractPemContents(request.getPem());

            // Create Digital Identity's header
            byte[] headerBytes = {(byte)0xEC, 0x01, (byte)0xAC, 0x01, (byte)0xFF, (byte)0xFF};
            String header = Base64.getEncoder().encodeToString(headerBytes);
            String jws = this.hsmSigner.createJws(toolPubkey + request.getDeviceAlternateId());
            // Generate jws of combined public key and alternateId
            return header
                    + "."
                    + Base64.getEncoder().encodeToString(request.getDeviceAlternateId().getBytes())
                    + "."
                    + toolPubkey
                    + "."
                    + jws;

        } catch (JOSEException exc) {
            logger.error("constructDigitalIdentity exception: ", exc);
            throw new CloudBasicException(INTERNAL_ERROR_SERVICE_ERROR, "Unable to construct the digital identity");
        }
    }

    // Build Digital Identity to be sent back
    private void createServiceResponseAsDigitalIdentity(CallContext callContext, boolean created)
    {
        DigitalIdentity di = new DigitalIdentity(callContext.getTid(), callContext.getDigitalIdentityRecord());
        JsonNode json = Json.toJson(di);
        callContext.setResult(created ? created(json) : ok(json));
        logger.info("Service response: {}", created ? "created" : "ok");
    }

    private void findDigitalIdentityRecord(CallContext callContext)
    {
        try {
            callContext.setDigitalIdentityRecord(DigitalIdentityModel
                    .findById(this.digitalIdentityStore, callContext.getTid()));
            logger.info("{} was {}found in the service database",
                    callContext.getTid(),
                    callContext.getDigitalIdentityRecord() != null ? "" : "not ");
        } catch (Exception exception) {
            logger.error("findDigitalEntityRecord exception: ", exception.getMessage());
            callContext.setDigitalIdentityRecord(null);
        }
    }

    private void createDigitalIdentityRecord(CallContext callContext)
    {
        prepareDigitalIdentityRecord(callContext);
        callContext.getDigitalIdentityRecord().save();
        logger.info("{} was created in the database", callContext.getTid());
    }

    // assign the new device public key
    private void updateDigitalIdentityRecord(CallContext callContext)
    {
        prepareDigitalIdentityRecord(callContext);
        callContext.getDigitalIdentityRecord().update();
        logger.info("{} was updated in the database", callContext.getTid());
    }

    private void prepareDigitalIdentityRecord(CallContext callContext)
    {
        DigitalIdentityModel record =
                new DigitalIdentityModel(this.digitalIdentityStore,
                                            callContext.getRequest(),
                                            constructDigitalIdentity(callContext.getRequest()));

        callContext.setDigitalIdentityRecord(record);
    }

    private void verifyToolId(String toolID) throws CloudValidationException
    {
        if (!DigitalIdentity.idIsValid(toolID)) {
            ArrayList<ValidationError> errors = new ArrayList<>();
            errors.add(new ValidationError("deviceAlternateId", DigitalIdentity.validIdHint()));
            throw new CloudValidationException(errors);
        }
        logger.info("{} is the valid tool identifier", toolID);
    }

    private void lockTID(CallContext callContext)
    {
        DigitalIdentityLockModel lock =
                new DigitalIdentityLockModel(this.digitalIdentityStore, callContext.getRequest());
        try {
            if (lock.obtain() == DigitalIdentityLockModel.LockResult.LOCKED_BY_OTHER)
                throw new CloudBasicException(CONFLICT_RESOURCE_EXISTS,
                        callContext.getTid() + " is currently being executed in another request");
        } catch (DbStoreException pe) {
            throw new CloudBasicException(INTERNAL_ERROR_SERVICE_ERROR, pe.getMessage());
        }
        callContext.setLock(lock);
        logger.info("{} locked", callContext.getTid());
    }

    private IoTDataMessage parseValidateSignatureRequest(Http.Request request)  throws CloudValidationException
    {
        ArrayList<ValidationError> errors = new ArrayList<>();
        Optional<IoTDataMessage> optionalMessage = request.body().parseJson(IoTDataMessage.class);
        IoTDataMessage msg = null;

        if(!optionalMessage.isPresent())
            errors.add(new ValidationError("payload", "received message has an incorrect format"));

        else {
            msg = optionalMessage.get();

            String capabilityAlternateId = msg.getCapabilityAlternateId();

            if (capabilityAlternateId == null)
                errors.add(new ValidationError( "capabilityAlternateId", THE_FIELD_IS_MISSING_IN_PAYLOAD));
            else if (!"signature".equals(capabilityAlternateId))
                errors.add(new ValidationError( "capabilityAlternateId", "field value should be equal 'signature'"));
            else if (msg.hasNoMeasures())
                errors.add(new ValidationError("measures", "the list of measures is either missing or empty"));
            else
                validateMeasures(msg.getMeasures(), errors);
        }

        if (!errors.isEmpty())
            throw new CloudValidationException(errors);
        return msg;
    }

    private void validateMeasures(IoTMeasure[] measures, ArrayList<ValidationError> errors)
    {
        for (IoTMeasure measure : measures) {
            String signerAlternateId = measure.getSignerAlternateId();

            verifyToolId(signerAlternateId);
            String key = "measures(" + signerAlternateId + ").jws";
            if (measure.getJws() == null)
                errors.add(new ValidationError(key, THE_FIELD_IS_MISSING_IN_PAYLOAD));
            else if (!Pattern.matches(patternJws, measure.getJws()))
                errors.add(new ValidationError(key, "Incorrect format of jws payload"));
        }
    }

    private String decodeMeasure(IoTMeasure measure, DigitalIdentityModel record)
    {
        String errMsgPrefix = "measure[" + measure.getSignerAlternateId() + "] - ";

        try {
            JWSObject jws = JWSObject.parse(measure.getJws());
            logger.debug("jws extracted");

            // Extract device public key from the Digital Identity Signing Request
            ECPublicKey publicKey = KeyRoutines.extractPublicKey(record.getPublicKey());
            logger.debug("public key extracted");

            // Verify the signature using the device public key
            JWSVerifier verifier = new ECDSAVerifier(publicKey);
            if (!jws.verify(verifier))
                throw new CloudBasicException(ErrorCode.BAD_REQUEST, errMsgPrefix + "Java Web Signature validation failure");
            logger.debug("jws verified");

            return jws.getPayload().toString();
        } catch(ParseException parseexc) {
            throw new CloudBasicException(ErrorCode.BAD_REQUEST, errMsgPrefix + "Unable to parse JWS");
        } catch(IOException | NoSuchAlgorithmException | InvalidKeySpecException keyexc) {
            throw new CloudBasicException(ErrorCode.BAD_REQUEST,
                    errMsgPrefix + "Unable to parse the device public key: " + keyexc.getMessage());
        } catch(JOSEException jwsexc) {
            throw new CloudBasicException(ErrorCode.BAD_REQUEST,
                    errMsgPrefix + "JWS verification error: " + jwsexc.getMessage());
        }
    }

    private CallContext initRequestProcessing(final Http.Request request)
    {
        MDC.put("transaction_id", request.getHeaders().get(TRANSACTION_HEADER).orElse("<none>"));
        MDC.put("service", serviceName);
        logger.info("{} {}", request.method(), request.path());

        return new CallContext();
    }

    private void finishRequestProcessing(CallContext callContext)
    {
        try {
            if (callContext.getLock() != null) {
                logger.info("Releasing {} lock of {}", callContext.getLock().isHolding() ? "own" : "", callContext.getTid());
                callContext.getLock().release();
                callContext.clearLock();
            }
            MDC.remove("transaction_id");
        } catch(Exception ex) {
            logger.error("finishRequestProcessing exception: ", ex);
        }
    }

    private Result handleException(Throwable exc, CallContext callContext) throws CloudBasicException, CloudValidationException
    {
        try {
            if (exc.getCause() instanceof CloudBasicException) {
                CloudBasicException cbe = (CloudBasicException) exc.getCause();
                logger.error(cbe.getDetails());
                throw cbe;
            }

            if (exc.getCause() instanceof CloudValidationException) {
                CloudValidationException cve = (CloudValidationException) exc.getCause();
                String msg = cve.getValidationErrors().stream().map(err -> err.key() + ": " + err.message())
                        .collect(Collectors.joining("; "));
                logger.error(msg);
                throw cve;
            }

            logger.error("Not handled exception: ", exc);
            throw new CloudBasicException(INTERNAL_ERROR_SERVICE_ERROR, exc.getMessage());

        } finally {
            finishRequestProcessing(callContext);
        }
    }
}
