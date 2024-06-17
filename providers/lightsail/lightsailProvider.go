package lightsail

import (
	"context"
	"encoding/json"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/providers"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	ls "github.com/aws/aws-sdk-go-v2/service/lightsail"
)

var (
	// lightsail has a fixed TTL of 172800 seconds for Apex NS records
	fixedNSTTL = uint32(172800)
	// lightsail has a fixed TTL of 60 seconds for other records
	fixedTTL = uint32(60)
)

type lightsailProvider struct {
	client *ls.Client
}

func newDsp(conf map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	return newLightsail(conf, metadata)
}

func newLightsail(m map[string]string, _ json.RawMessage) (*lightsailProvider, error) {
	optFns := []func(*config.LoadOptions) error{
		// Domain-related APIs are only available in the us-east-1 Region.
		config.WithRegion("us-east-1"),
	}

	keyID, secretKey, tokenID := m["KeyId"], m["SecretKey"], m["Token"]
	// Token is optional and left empty unless required
	if keyID != "" || secretKey != "" {
		optFns = append(optFns, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(keyID, secretKey, tokenID)))
	}

	config, err := config.LoadDefaultConfig(context.Background(), optFns...)
	if err != nil {
		return nil, err
	}

	api := &lightsailProvider{client: ls.NewFromConfig(config)}
	return api, nil
}

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	// See providers/capabilities.go for the entire list of capabilities.
	providers.CanGetZones:            providers.Can(),
	providers.CanConcur:              providers.Cannot(),
	providers.CanUseAlias:            providers.Cannot(),
	providers.CanUseCAA:              providers.Cannot(),
	providers.CanUseHTTPS:            providers.Cannot(),
	providers.CanUseLOC:              providers.Cannot(),
	providers.CanUsePTR:              providers.Cannot(),
	providers.CanUseSRV:              providers.Can(),
	providers.DocCreateDomains:       providers.Can(),
	providers.DocDualHost:            providers.Cannot(),
	providers.DocOfficiallySupported: providers.Cannot(),
}

func init() {
	fns := providers.DspFuncs{
		Initializer:   newDsp,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType("LIGHTSAIL", fns, features)
}

func (r *lightsailProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	zone, err := r.getZone(domain)
	if err != nil {
		return nil, err
	}

	nss := []string{}
	for _, entry := range zone.DomainEntries {
		if aws.ToString(entry.Type) == "NS" && aws.ToString(entry.Name) == domain {
			nss = append(nss, aws.ToString(entry.Target))
		}
	}
	return models.ToNameservers(nss)
}
