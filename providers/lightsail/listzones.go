package lightsail

import (
	"context"
	"strings"

	"github.com/StackExchange/dnscontrol/v4/pkg/printer"
	ls "github.com/aws/aws-sdk-go-v2/service/lightsail"
)

func (r *lightsailProvider) EnsureZoneExists(domain string) error {
	if _, err := r.getZone(domain); err != nil {
		if strings.Contains(err.Error(), "not authorized") {
			return err
		}
		printer.Printf("Adding zone for %s to lightsail account\n", domain)
		in := &ls.CreateDomainInput{
			DomainName: &domain,
		}

		withRetry(func() error {
			_, err = r.client.CreateDomain(context.Background(), in)
			return err
		})
		return err
	}
	return nil
}

// ListZones lists the zones on this account.
func (r *lightsailProvider) ListZones() ([]string, error) {
	domains, err := r.getZones()
	if err != nil {
		return nil, err
	}
	var zones []string
	for _, domain := range domains {
		zones = append(zones, *domain.Name)
	}
	return zones, nil
}
