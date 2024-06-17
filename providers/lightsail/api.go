package lightsail

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/StackExchange/dnscontrol/v4/pkg/printer"
	ls "github.com/aws/aws-sdk-go-v2/service/lightsail"
	lsTypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
)

func (r *lightsailProvider) getZones() ([]lsTypes.Domain, error) {
	var nextPageToken *string
	zones := []lsTypes.Domain{}
	for {
		var out *ls.GetDomainsOutput
		var err error
		withRetry(func() error {
			inp := &ls.GetDomainsInput{PageToken: nextPageToken}
			out, err = r.client.GetDomains(context.Background(), inp)
			return err
		})
		if err != nil && strings.Contains(err.Error(), "security token included in the request is invalid") {
			return nil, errors.New("check your credentials, you're not authorized to perform actions on AWS Lightsail Domains Service")
		} else if err != nil {
			return nil, err
		}
		zones = append(zones, out.Domains...)
		if out.NextPageToken != nil {
			nextPageToken = out.NextPageToken
		} else {
			break
		}
	}
	return zones, nil
}

func (r *lightsailProvider) getZone(domain string) (*lsTypes.Domain, error) {
	var out *ls.GetDomainOutput
	var err error
	withRetry(func() error {
		inp := &ls.GetDomainInput{DomainName: &domain}
		out, err = r.client.GetDomain(context.Background(), inp)
		return err
	})
	if err != nil && strings.Contains(err.Error(), "security token included in the request is invalid") {
		return nil, errors.New("check your credentials, you're not authorized to perform actions on AWS Lightsail Domains Service")
	} else if err != nil {
		return nil, err
	}
	return out.Domain, nil
}

func (r *lightsailProvider) createDomainEntry(entry *lsTypes.DomainEntry, domain string) error {
	in := &ls.CreateDomainEntryInput{
		DomainName:  &domain,
		DomainEntry: entry,
	}
	var err error
	withRetry(func() error {
		_, err = r.client.CreateDomainEntry(context.Background(), in)
		return err
	})
	return err
}

func (r *lightsailProvider) deleteDomainEntry(entry *lsTypes.DomainEntry, domain string) error {
	in := &ls.DeleteDomainEntryInput{
		DomainName:  &domain,
		DomainEntry: entry,
	}
	var err error
	withRetry(func() error {
		_, err = r.client.DeleteDomainEntry(context.Background(), in)
		return err
	})
	return err
}

func (r *lightsailProvider) updateDomainEntry(entry *lsTypes.DomainEntry, domain string) error {
	in := &ls.UpdateDomainEntryInput{
		DomainName:  &domain,
		DomainEntry: entry,
	}
	var err error
	withRetry(func() error {
		_, err = r.client.UpdateDomainEntry(context.Background(), in)
		return err
	})
	return err
}

// rate exceeded error message:
// "The maximum API request rate has been exceeded for your account.
// Please try your request again shortly.
// For best results using the Lightsail API, use an increased time interval between requests."
func withRetry(f func() error) {
	const maxRetries = 23
	const sleepTime = 5 * time.Second
	var currentRetry int
	for {
		err := f()
		if err == nil {
			return
		}
		if strings.Contains(err.Error(), "rate has been exceeded") {
			currentRetry++
			if currentRetry >= maxRetries {
				return
			}
			printer.Printf("============ Lightsail rate limit exceeded. Waiting %s to retry.\n", sleepTime)
			time.Sleep(sleepTime)
		} else {
			return
		}
	}
}
