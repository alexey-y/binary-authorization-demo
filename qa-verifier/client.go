package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
)

type attestor struct {
	Name        string `json:"name"`
	Description string `json:"description"`

	UserOwnedDrydockNote *struct {
		NoteReference string `json:"noteReference"`
	} `json:"userOwnedDrydockNote"`
}

// NoteID returns the note from the attestor.
func (a *attestor) NoteID() string {
	if a == nil || a.UserOwnedDrydockNote == nil {
		return ""
	}
	return a.UserOwnedDrydockNote.NoteReference
}

// Attestor downloads the given attestor. id is projects/<p>/attestors/<a>.
func Attestor(ctx context.Context, id string) (*attestor, error) {
	u := fmt.Sprintf("https://binaryauthorization.googleapis.com/v1beta1/%s", id)

	var a attestor
	if err := get(ctx, u, &a); err != nil {
		return nil, fmt.Errorf("failed to get attestor: %w", err)
	}
	return &a, nil
}

type digest struct {
	Digest sha512Digest `json:"digest"`
}

type sha512Digest struct {
	SHA512 []byte `json:"sha512"`
}

type signature struct {
	Signature []byte `json:"signature"`
}

func KMSSign(ctx context.Context, id string, d *digest) (*signature, error) {
	u := fmt.Sprintf("https://cloudkms.googleapis.com/v1/%s:asymmetricSign", id)

	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("failed to create json for signing: %w", err)
	}

	var s signature
	if err := post(ctx, u, bytes.NewReader(b), &s); err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return &s, nil
}

type payloadMessage struct {
	Critical *payload `json:"critical"`
}

type payload struct {
	Identity *payloadIdentity `json:"identity"`
	Image    *payloadImage    `json:"image"`
	Type     string
}

type payloadIdentity struct {
	DockerReference string `json:"docker-reference"`
}

type payloadImage struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

func PayloadFor(repo, sha string) ([]byte, error) {
	p := &payloadMessage{
		Critical: &payload{
			Identity: &payloadIdentity{
				DockerReference: repo,
			},
			Image: &payloadImage{
				DockerManifestDigest: sha,
			},
			Type: "Google cloud binauthz container signature",
		},
	}

	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("failed to create payload: %w", err)
	}
	return b, nil
}

type occurrence struct {
	Attestation *occurrenceAttestation `json:"attestation"`
	Kind        string                 `json:"kind"`
	NoteName    string                 `json:"noteName"`
	Resource    *occurrenceResource    `json:"resource"`
}

type occurrenceAttestation struct {
	Attestation *attestation `json:"attestation"`
}

type attestation struct {
	GeneraticSignedAttestation *genericSignedAttestation `json:"genericSignedAttestation"`
}

type genericSignedAttestation struct {
	ContentType       string                 `json:"contentType"`
	SerializedPayload []byte                 `json:"serializedPayload"`
	Signatures        []*occurrenceSignature `json:"signatures"`
}

type occurrenceSignature struct {
	PublicKeyID string `json:"publicKeyId"`
	Signature   []byte `json:"signature"`
}

type occurrenceResource struct {
	URI string `json:"uri"`
}

func CreateOccurrence(ctx context.Context, noteID, imageID, keyID string, payload, sig []byte) error {
	// extract project ID from the noteID
	parts := strings.Split(noteID, "/")
	if len(parts) < 4 {
		return fmt.Errorf("invalid noteID %q", noteID)
	}

	projectID := parts[1]

	u := fmt.Sprintf("https://containeranalysis.googleapis.com/v1beta1/projects/%s/occurrences", projectID)

	o := &occurrence{
		Attestation: &occurrenceAttestation{
			Attestation: &attestation{
				GeneraticSignedAttestation: &genericSignedAttestation{
					ContentType:       "SIMPLE_SIGNING_JSON",
					SerializedPayload: payload,
					Signatures: []*occurrenceSignature{
						&occurrenceSignature{
							PublicKeyID: fmt.Sprintf("//cloudkms.googleapis.com/v1/%s", keyID), // projects/<p>/locations/<l>/keyRings/<kr>/cryptoKeys/<k>/cryptoKeyVersions/<v>
							Signature:   sig,
						},
					},
				},
			},
		},
		Kind:     "ATTESTATION",
		NoteName: noteID, // projects/<p>/notes/<n>
		Resource: &occurrenceResource{
			URI: fmt.Sprintf("https://%s", imageID), // gcr.io/<p>/demo-app@sha256:<sha>
		},
	}

	b, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("failed to create json for occurrence: %w", err)
	}

	if err := post(ctx, u, bytes.NewReader(b), nil); err != nil {
		return fmt.Errorf("failed to create occurrence: %w", err)
	}
	return nil
}

func get(ctx context.Context, u string, i interface{}) error {
	return request(ctx, http.MethodGet, u, nil, i)
}

func post(ctx context.Context, u string, r io.Reader, i interface{}) error {
	return request(ctx, http.MethodPost, u, r, i)
}

func request(ctx context.Context, m string, u string, r io.Reader, i interface{}) error {
	client, err := google.DefaultClient(ctx, iam.CloudPlatformScope)
	if err != nil {
		return fmt.Errorf("failed to create http client: %w", err)
	}

	req, err := http.NewRequest(m, u, r)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if err := googleapi.CheckResponse(resp); err != nil {
		return fmt.Errorf("bad api response: %w", err)
	}

	if i != nil {
		if err := json.NewDecoder(resp.Body).Decode(i); err != nil {
			return fmt.Errorf("failed to decode json: %w", err)
		}
	}

	return nil
}
