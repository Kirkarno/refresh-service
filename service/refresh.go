package service

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/0xPolygonID/refresh-service/providers/flexiblehttp"
	core "github.com/iden3/go-iden3-core/v2"
	jsonproc "github.com/iden3/go-schema-processor/v2/json"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/processor"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

var (
	ErrCredentialNotUpdatable = errors.New("not updatable")
	errIndexSlotsNotUpdated   = errors.New("no index fields were updated")
)

type RefreshService struct {
	issuerService  *IssuerService
	documentLoader ld.DocumentLoader
	providers      flexiblehttp.FactoryFlexibleHTTP
}

func NewRefreshService(
	issuerService *IssuerService,
	documentLoader ld.DocumentLoader,
	providers flexiblehttp.FactoryFlexibleHTTP,
) *RefreshService {
	return &RefreshService{
		issuerService:  issuerService,
		documentLoader: documentLoader,
		providers:      providers,
	}
}

type credentialRequest struct {
	CredentialSchema  string                     `json:"credentialSchema"`
	Type              string                     `json:"type"`
	CredentialSubject map[string]interface{}     `json:"credentialSubject"`
	Expiration        int64                      `json:"expiration"`
	RefreshService    *verifiable.RefreshService `json:"refreshService,omitempty"`
	RevNonce          *uint64                    `json:"revNonce,omitempty"`
	DisplayMethod     *verifiable.DisplayMethod  `json:"displayMethod,omitempty"`
}

func (rs *RefreshService) Process(
	ctx context.Context,
	issuer, owner, id string,
) (*verifiable.W3CCredential, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("🔥 Panic recovered in Process: %v", r)
		}
	}()

	if rs.issuerService == nil {
		return nil, errors.New("issuerService is nil")
	}
	if rs.documentLoader == nil {
		return nil, errors.New("documentLoader is nil")
	}

	log.Printf("🔄 Starting refresh for credential ID: %s", id)

	credential, err := rs.issuerService.GetClaimByID(issuer, id)
	if err != nil {
		log.Printf("❌ Failed to fetch credential from issuer: %v", err)
		return nil, err
	}
	if credential == nil {
		return nil, errors.New("GetClaimByID returned nil credential")
	}

	credentialJSON, _ := json.MarshalIndent(credential, "", "  ")
	log.Printf("🧾 Full credential:\n%s", credentialJSON)

	log.Printf("🔎 Parsed credential — issuer: '%s', type: '%v', subject: %+v",
		credential.Issuer, credential.Type, credential.CredentialSubject)

	if credential.Issuer == "" {
		return nil, errors.New("credential issuer is empty")
	}

	if credential.ID == "" {
		return nil, errors.New("credential ID is empty")
	}

	if credential.Type == nil {
		return nil, errors.New("credential type is nil")
	}

	if credential.Expiration == nil {
		return nil, errors.New("credential expiration is nil")
	}

	if credential.CredentialSubject == nil {
		return nil, errors.New("credential subject is nil")
	}

	if err := isUpdatable(credential); err != nil {
		return nil, errors.Wrapf(ErrCredentialNotUpdatable, "credential '%s': %v", credential.ID, err)
	}

	if err := checkOwnerShip(credential, owner); err != nil {
		return nil, errors.Wrapf(ErrCredentialNotUpdatable, "credential '%s': %v", credential.ID, err)
	}

	credentialBytes, _ := json.Marshal(credential)

	typeValue, exists := credential.CredentialSubject["type"]
	if !exists {
		return nil, errors.New("type field missing in credentialSubject")
	}

	if typeValue == nil {
		return nil, errors.New("type field is nil in credentialSubject")
	}

	subjectType, ok := typeValue.(string)
	if !ok || subjectType == "" {
		return nil, errors.New("invalid or missing type in credentialSubject")
	}

	credentialType, err := merklize.Options{
		DocumentLoader: rs.documentLoader,
	}.TypeIDFromContext(credentialBytes, subjectType)
	if err != nil {
		return nil, err
	}

	flexibleHTTP, err := rs.providers.ProduceFlexibleHTTP(credentialType)
	if err != nil {
		return nil, errors.Wrapf(ErrCredentialNotUpdatable, "for credential '%s' no provider: %v", credential.ID, err)
	}

	updatedFields, err := flexibleHTTP.Provide(credential.CredentialSubject)
	if err != nil {
		return nil, err
	}

	if updatedFields == nil {
		log.Printf("⚠️ Warning: updatedFields is nil, using empty map")
		updatedFields = make(map[string]interface{})
	}

	if flexibleHTTP.Settings.TimeExpiration == 0 {
		log.Printf("⚠️ Warning: TimeExpiration is 0, using default 5 minutes")
		flexibleHTTP.Settings.TimeExpiration = 5 * time.Minute
	}

	if err := rs.isUpdatedIndexSlots(ctx, credential, credential.CredentialSubject, updatedFields); err != nil {
		return nil, errors.Wrapf(ErrCredentialNotUpdatable, "index update fail: %v", err)
	}

	for k, v := range updatedFields {
		credential.CredentialSubject[k] = v
	}

	revNonce, err := extractRevocationNonce(credential)
	if err != nil {
		return nil, err
	}

	if credential.CredentialSchema.ID == "" {
		return nil, errors.New("credential schema ID is empty")
	}

	if credential.RefreshService == nil {
		log.Printf("⚠️ Warning: RefreshService is nil")
	}

	if credential.DisplayMethod == nil {
		log.Printf("⚠️ Warning: DisplayMethod is nil")
	}

	credReq := credentialRequest{
		CredentialSchema:  credential.CredentialSchema.ID,
		Type:              subjectType,
		CredentialSubject: credential.CredentialSubject,
		Expiration:        time.Now().Add(flexibleHTTP.Settings.TimeExpiration).Unix(),
		RefreshService:    credential.RefreshService,
		RevNonce:          &revNonce,
		DisplayMethod:     credential.DisplayMethod,
	}

	refreshedID, err := rs.issuerService.CreateCredential(issuer, credReq)
	if err != nil {
		return nil, err
	}

	return rs.issuerService.GetClaimByID(issuer, refreshedID)
}

func isUpdatable(credential *verifiable.W3CCredential) error {
	if credential == nil {
		return errors.New("nil credential")
	}

	if credential.Expiration == nil {
		return errors.New("credential expiration is nil")
	}

	if credential.Expiration.After(time.Now()) {
		return errors.New("not expired")
	}

	if credential.CredentialSubject == nil {
		return errors.New("credential subject is nil")
	}

	idValue, exists := credential.CredentialSubject["id"]
	if !exists {
		return errors.New("id field missing in credentialSubject")
	}

	if idValue == nil {
		return errors.New("id field is nil in credentialSubject")
	}

	idVal, ok := idValue.(string)
	if !ok || strings.TrimSpace(idVal) == "" {
		return errors.New("credential subject does not have a valid id")
	}
	return nil
}

func checkOwnerShip(credential *verifiable.W3CCredential, owner string) error {
	if credential == nil {
		return errors.New("nil credential")
	}

	if credential.CredentialSubject == nil {
		return errors.New("credential subject is nil")
	}

	idValue, exists := credential.CredentialSubject["id"]
	if !exists {
		return errors.New("credential subject does not have an id field")
	}

	if idValue != owner {
		return errors.New("not owner of the credential")
	}
	return nil
}

func (rs *RefreshService) isUpdatedIndexSlots(
	ctx context.Context,
	credential *verifiable.W3CCredential,
	oldValues, newValues map[string]interface{},
) error {
	if credential == nil {
		return errors.New("nil credential in isUpdatedIndexSlots")
	}

	claim, err := jsonproc.Parser{}.ParseClaim(ctx, *credential, &processor.CoreClaimOptions{
		MerklizerOpts: []merklize.MerklizeOption{
			merklize.WithDocumentLoader(rs.documentLoader),
		},
	})
	if err != nil {
		return errors.Errorf("invalid w3c credential: %v", err)
	}

	merklizedRootPosition, err := claim.GetMerklizedPosition()
	if err != nil {
		return errors.Errorf("failed to get merklized position: %v", err)
	}

	switch merklizedRootPosition {
	case core.MerklizedRootPositionIndex:
		return nil
	case core.MerklizedRootPositionValue:
		return errIndexSlotsNotUpdated
	case core.MerklizedRootPositionNone:

		if credential.Context == nil {
			log.Printf("⚠️ Warning: credential.Context is nil, using empty contexts")
			credential.Context = []string{}
		}

		credentialBytes, err := rs.loadContexts(credential.Context)
		if err != nil {
			return errors.Errorf("failed to load contexts: %v", err)
		}
		for k, v := range oldValues {
			if k == "type" || k == "id" {
				continue
			}

			typeValue, ok := oldValues["type"]
			if !ok || typeValue == nil {
				log.Printf("⚠️ Warning: type field is missing or nil in oldValues")
				continue
			}

			typeStr, ok := typeValue.(string)
			if !ok {
				log.Printf("⚠️ Warning: type field is not a string in oldValues")
				continue
			}

			slotIndex, err := jsonproc.Parser{}.GetFieldSlotIndex(
				k, typeStr, credentialBytes)
			if err != nil && strings.Contains(err.Error(), "not specified in serialization info") {
				return nil
			} else if err != nil {
				return err
			}

			newValue, exists := newValues[k]
			if !exists {
				log.Printf("⚠️ Warning: field %s not found in newValues", k)
				continue
			}

			if (slotIndex == 2 || slotIndex == 3) && v != newValue {
				return nil
			}
		}
	}
	return errIndexSlotsNotUpdated
}

func (rs *RefreshService) loadContexts(contexts []string) ([]byte, error) {
	if rs.documentLoader == nil {
		return nil, errors.New("documentLoader is nil in loadContexts")
	}

	if contexts == nil || len(contexts) == 0 {
		log.Printf("⚠️ Warning: contexts is nil or empty")
		return json.Marshal(map[string]interface{}{"@context": []interface{}{}})
	}

	type uploadedContexts struct {
		Contexts []interface{} `json:"@context"`
	}
	var res uploadedContexts
	for _, context := range contexts {
		if context == "" {
			log.Printf("⚠️ Warning: empty context string, skipping")
			continue
		}

		remoteDocument, err := rs.documentLoader.LoadDocument(context)
		if err != nil {
			log.Printf("⚠️ Warning: failed to load context '%s': %v", context, err)
			continue
		}

		if remoteDocument == nil || remoteDocument.Document == nil {
			log.Printf("⚠️ Warning: remoteDocument or Document is nil for context '%s'", context)
			continue
		}

		document, ok := remoteDocument.Document.(map[string]interface{})
		if !ok {
			log.Printf("⚠️ Warning: Document is not a map for context '%s'", context)
			continue
		}

		ldContext, ok := document["@context"]
		if !ok {
			log.Printf("⚠️ Warning: @context key not found in context '%s'", context)
			continue
		}

		if v, ok := ldContext.([]interface{}); ok {
			res.Contexts = append(res.Contexts, v...)
		} else {
			res.Contexts = append(res.Contexts, ldContext)
		}
	}
	return json.Marshal(res)
}

func extractRevocationNonce(credential *verifiable.W3CCredential) (uint64, error) {
	if credential == nil {
		return 0, errors.New("nil credential in extractRevocationNonce")
	}
	credentialStatusInfo, ok := credential.CredentialStatus.(map[string]interface{})
	if !ok {
		return 0, errors.New("invalid credential status")
	}
	nonce, ok := credentialStatusInfo["revocationNonce"]
	if !ok {
		return 0, errors.New("revocationNonce not found in credential status")
	}
	n, ok := nonce.(float64)
	if !ok {
		return 0, errors.New("revocationNonce is not a number")
	}
	return uint64(n), nil
}
