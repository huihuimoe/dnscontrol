package lightsail

import (
	"fmt"
	"strings"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/txtutil"

	"github.com/aws/aws-sdk-go-v2/aws"
	lsTypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
)

func nativeToRecord(entry *lsTypes.DomainEntry, origin string) (*models.RecordConfig, error) {
	ttl := fixedTTL
	if aws.ToBool(entry.IsAlias) {
		return nil, fmt.Errorf("alias records not yet supported")
	} else {
		typeString := aws.ToString(entry.Type)
		val := aws.ToString(entry.Target)

		if typeString == "CNAME" || typeString == "MX" || typeString == "SRV" || typeString == "NS" {
			if !strings.HasSuffix(val, ".") {
				val = val + "."
			}
		}

		// fix Apex NS TTL
		if typeString == "NS" && aws.ToString(entry.Name) == origin {
			ttl = fixedNSTTL
		}

		rc := &models.RecordConfig{TTL: ttl}
		rc.SetLabelFromFQDN(unescape(entry.Name), origin)
		rc.Original = entry
		if err := rc.PopulateFromStringFunc(typeString, val, origin, txtutil.ParseQuoted); err != nil {
			return nil, fmt.Errorf("unparsable record type=%q received from LIGHTSAIL: %w", typeString, err)
		}

		return rc, nil
	}
}

func recordToNative(rc *models.RecordConfig) (*lsTypes.DomainEntry, error) {
	var val string
	if rc.Type == "TXT" {
		val = rc.GetTargetTXTJoined()
		val = txtutil.EncodeQuoted(val)
	} else {
		val = rc.GetTargetCombined()
	}
	result := &lsTypes.DomainEntry{
		Name:    aws.String(rc.GetLabelFQDN()),
		IsAlias: aws.Bool(false),
		Target:  aws.String(val),
		Type:    aws.String(rc.Type),
	}

	return result, nil
}

// process names to match what we expect and to remove their odd octal encoding
func unescape(s *string) string {
	if s == nil {
		return ""
	}
	name := strings.TrimSuffix(*s, ".")
	name = strings.Replace(name, `\052`, "*", -1) // escape all octal sequences
	return name
}
