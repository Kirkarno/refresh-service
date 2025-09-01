package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/0xPolygonID/refresh-service/logger"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/pkg/errors"
)

var (
	ErrIssuerNotSupported = errors.New("issuer is not supported")
	ErrGetClaim           = errors.New("failed to get claim")
	ErrCreateClaim        = errors.New("failed to create claim")
)

type IssuerService struct {
	supportedIssuers map[string]string
	issuerBasicAuth  map[string]string
	client           *http.Client
}

func NewIssuerService(
	supportedIssuers map[string]string,
	issuerBasicAuth map[string]string,
	client *http.Client,
) *IssuerService {
	if client == nil {
		client = http.DefaultClient
	}
	return &IssuerService{
		supportedIssuers: supportedIssuers,
		issuerBasicAuth:  issuerBasicAuth,
		client:           client,
	}
}

// GetClaimByID получает VC по DID и claimID
func (is *IssuerService) GetClaimByID(issuerDID, claimID string) (*verifiable.W3CCredential, error) {
	issuerNode, err := is.getIssuerURL(issuerDID)
	if err != nil {
		return nil, err
	}
	logger.DefaultLogger.Infof("use issuer node '%s' for issuer '%s'", issuerNode, issuerDID)

	url := fmt.Sprintf("%s/v2/identities/%s/credentials/%s", issuerNode, issuerDID, claimID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrapf(ErrGetClaim, "failed to create http request: %v", err)
	}

	if err := is.setBasicAuth(issuerDID, req); err != nil {
		return nil, err
	}

	resp, err := is.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(ErrGetClaim, "failed http GET request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrapf(ErrGetClaim, "invalid status code: %d", resp.StatusCode)
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(ErrGetClaim, "failed to read response body: %v", err)
	}
	log.Printf("📡 Raw response from issuer node (%s):\n%s", url, string(rawBody))

	var response struct {
		VC verifiable.W3CCredential `json:"vc"`
	}
	if err := json.Unmarshal(rawBody, &response); err != nil {
		return nil, errors.Wrapf(ErrGetClaim, "failed to decode response: %v", err)
	}

	log.Printf("✅ Parsed VC: %+v\n", response.VC)
	return &response.VC, nil
}

// CreateCredential создает VC
func (is *IssuerService) CreateCredential(issuerDID string, credentialRequest credentialRequest) (string, error) {
	issuerNode, err := is.getIssuerURL(issuerDID)
	if err != nil {
		return "", err
	}
	logger.DefaultLogger.Infof("use issuer node '%s' for issuer '%s'", issuerNode, issuerDID)

	body, err := json.Marshal(credentialRequest)
	if err != nil {
		return "", errors.Wrap(ErrCreateClaim, "credential request serialization error")
	}

	url := fmt.Sprintf("%s/v2/identities/%s/credentials", issuerNode, issuerDID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return "", errors.Wrapf(ErrCreateClaim, "failed to create http request: %v", err)
	}

	if err := is.setBasicAuth(issuerDID, req); err != nil {
		return "", err
	}

	resp, err := is.client.Do(req)
	if err != nil {
		return "", errors.Wrapf(ErrCreateClaim, "failed http POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", errors.Wrap(ErrCreateClaim, "invalid status code")
	}

	var responseBody struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return "", errors.Wrapf(ErrCreateClaim, "failed to decode response: %v", err)
	}

	return responseBody.ID, nil
}

// getIssuerURL возвращает URL issuer’а, универсальный "*" используется по умолчанию
func (is *IssuerService) getIssuerURL(issuerDID string) (string, error) {
	if url, ok := is.supportedIssuers[issuerDID]; ok {
		return url, nil
	}
	if url, ok := is.supportedIssuers["*"]; ok {
		return url, nil
	}
	return "", errors.Wrapf(ErrIssuerNotSupported, "id '%s'", issuerDID)
}

// setBasicAuth устанавливает логин/пароль, универсальный "*" используется по умолчанию
func (is *IssuerService) setBasicAuth(issuerDID string, req *http.Request) error {
	if is.issuerBasicAuth == nil {
		return nil
	}

	namepass, ok := is.issuerBasicAuth[issuerDID]
	if !ok {
		namepass, ok = is.issuerBasicAuth["*"]
		if !ok {
			logger.DefaultLogger.Warnf("issuer '%s' not found in basic auth map", issuerDID)
			return nil
		}
	}

	parts := strings.SplitN(namepass, ":", 2)
	if len(parts) != 2 {
		return errors.Errorf("invalid basic auth: %q", namepass)
	}

	req.SetBasicAuth(parts[0], parts[1])
	return nil
}
