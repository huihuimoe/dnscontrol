package lightsail

import (
	"fmt"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff2"
	"github.com/StackExchange/dnscontrol/v4/pkg/printer"
	"github.com/aws/aws-sdk-go-v2/aws"
	lsTypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
)

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (r *lightsailProvider) GetZoneRecords(domain string, meta map[string]string) (models.Records, error) {
	zone, err := r.getZone(domain)
	if err != nil {
		return nil, err
	}

	var existingRecords = []*models.RecordConfig{}
	for _, entry := range zone.DomainEntries {
		if aws.ToString(entry.Type) == "SOA" {
			continue
		}
		if aws.ToBool(entry.IsAlias) {
			printer.Warnf("alias records not yet supported. %s %s will be ignore.\n", aws.ToString(entry.Name), aws.ToString(entry.Type))
			continue
		}
		rts, err := nativeToRecord(&entry, domain)
		if err != nil {
			return nil, err
		}
		existingRecords = append(existingRecords, rts)
	}

	return existingRecords, nil
}

// GetZoneRecordsCorrections gets the corrections between the desired and existing records.
func (r *lightsailProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existingRecords models.Records) ([]*models.Correction, error) {
	var corrections []*models.Correction

	// fix ttl for records
	fixTTL(dc)

	changes, err := diff2.ByRecord(existingRecords, dc, nil)
	if err != nil {
		return nil, err
	}

	for _, change := range changes {
		msg := change.MsgsJoined
		if change.Type == diff2.REPORT {
			corrections = append(corrections, &models.Correction{Msg: msg})
			continue
		}
		if (change.Key.NameFQDN == dc.Name) && (change.Key.Type == "NS") {
			printer.Warnf("lightsail does not support modifying apex NS records. %s will not be affected.\n", msg)
			continue
		}

		var corr *models.Correction
		switch change.Type {
		case diff2.REPORT:
			corr = &models.Correction{Msg: msg}
		case diff2.CREATE:
			native, err := recordToNative(change.New[0])
			if err != nil {
				return nil, err
			}
			corr = &models.Correction{
				Msg: change.Msgs[0],
				F: func() error {
					return r.createDomainEntry(native, dc.Name)
				},
			}
		case diff2.CHANGE:
			oldID := change.Old[0].Original.(*lsTypes.DomainEntry).Id
			native, err := recordToNative(change.New[0])
			if err != nil {
				return nil, err
			}
			native.Id = oldID
			corr = &models.Correction{
				Msg: msg,
				F: func() error {
					return r.updateDomainEntry(native, dc.Name)
				},
			}
		case diff2.DELETE:
			old := change.Old[0].Original.(*lsTypes.DomainEntry)
			corr = &models.Correction{
				Msg: msg,
				F: func() error {
					return r.deleteDomainEntry(old, dc.Name)
				},
			}
		default:
			panic(fmt.Sprintf("unhandled change.Type %s", change.Type))
		}
		corrections = append(corrections, corr)
	}

	return corrections, nil
}

func fixTTL(dc *models.DomainConfig) {
	isWarnedNSTTL := false
	for _, rec := range dc.Records {
		if rec.Type == "NS" && rec.GetLabelFQDN() == dc.Name {
			if rec.TTL != fixedNSTTL {
				if !isWarnedNSTTL {
					printer.Warnf("lightsail does not support custom TTLs for apex NS records.\n")
					printer.Warnf("all apex NS records for domain %s will be set to ttl=%d.\n", rec.GetLabelFQDN(), fixedNSTTL)
					printer.Warnf("please make sure the NAMESERVER_TTL(%d) have set in your config file.\n", fixedNSTTL)
					isWarnedNSTTL = true
				}
				rec.TTL = fixedNSTTL
			}
		} else {
			if rec.TTL != 60 {
				printer.Warnf("lightsail does not support custom TTLs. \"%s\" will be set to ttl=%d.\n", rec.GetTargetDebug(), fixedTTL)
				rec.TTL = fixedTTL
			}
		}
	}
}
