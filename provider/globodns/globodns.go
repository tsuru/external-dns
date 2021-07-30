/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package globodns

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	gdns "github.com/tsuru/go-globodnsclient"
	"golang.org/x/oauth2/clientcredentials"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

type GloboDNSConfig struct {
	URL               string
	Token             string
	AuthMethod        string
	OAuthTokenURL     string
	OAuthClientID     string
	OAuthClientSecret string
	DomainFilter      endpoint.DomainFilter
	ZoneFilter        endpoint.DomainFilter
	ZoneIDFilter      provider.ZoneIDFilter
	RequestTimeout    time.Duration
	DocumentsPerPage  int
	DryRun            bool
}

func NewGloboDNSProvider(cfg GloboDNSConfig) (provider.Provider, error) {
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	client, err := gdns.New(httpClient, cfg.URL)
	if err != nil {
		return nil, err
	}

	if cfg.AuthMethod == "static" {
		client.SetToken(cfg.Token)
	}

	return NewGloboDNSProviderWithClient(client, cfg)
}

func NewGloboDNSProviderWithClient(c *gdns.Client, cfg GloboDNSConfig) (provider.Provider, error) {
	return &GloboDNSProvider{Client: c, Config: &cfg}, nil
}

var _ provider.Provider = &GloboDNSProvider{}

type GloboDNSProvider struct {
	*gdns.Client
	Config          *GloboDNSConfig
	domains         map[string]gdns.Domain
	domainsNameByID provider.ZoneIDName
}

type recordKey struct {
	Name string
	Type string
}

func (p *GloboDNSProvider) Records(ctx context.Context) (eps []*endpoint.Endpoint, err error) {
	domains, err := p.Domains(ctx)
	if err != nil {
		return nil, err
	}

	endpointByRecordKey := make(map[recordKey]*endpoint.Endpoint)

	for _, d := range domains {
		records, err := p.Record.List(ctx, d.ID, &gdns.ListRecordsParameters{PerPage: p.Config.DocumentsPerPage})
		if err != nil {
			return nil, err
		}

		log.Debugf("There are %d records in %s domain", len(records), d.Name)

		for _, r := range records {
			ep := newEndpoint(&d, &r)

			if !provider.SupportedRecordType(r.Type) {
				log.Debugf("Record type %s is not supported (from DNS record: %s), skipping it", ep.RecordType, ep.DNSName)
				continue
			}

			log.Debugf("Loading endpoint %v to current state", ep)

			rkey := recordKey{Name: r.Name, Type: r.Type}

			if e, found := endpointByRecordKey[rkey]; found {
				e.Targets = append(e.Targets, ep.Targets...)
				continue
			}

			endpointByRecordKey[rkey] = ep
		}
	}

	for _, ep := range endpointByRecordKey {
		eps = append(eps, ep)
	}

	// NOTE: required to keep unit tests predictable
	sort.SliceStable(eps, func(i, j int) bool {
		switch strings.Compare(eps[i].DNSName, eps[j].DNSName) {
		case -1:
			return true
		case 1:
			return false
		}

		return eps[i].RecordType < eps[j].RecordType
	})

	return eps, nil
}

func (p *GloboDNSProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) (err error) {
	if err := p.createRecords(ctx, changes.Create); err != nil {
		return err
	}

	if err := p.deleteRecords(ctx, changes.Delete); err != nil {
		return err
	}

	if err := p.updateRecords(ctx, changes.UpdateOld, changes.UpdateNew); err != nil {
		return err
	}

	if _, err := p.Bind.Export(ctx); err != nil {
		return err
	}

	return nil
}

func (p *GloboDNSProvider) PropertyValuesEqual(name string, previous string, current string) bool {
	return previous == current
}

func (p *GloboDNSProvider) AdjustEndpoints(endpoints []*endpoint.Endpoint) []*endpoint.Endpoint {
	return endpoints
}

func (p *GloboDNSProvider) GetDomainFilter() endpoint.DomainFilterInterface {
	return p.Config.DomainFilter
}

func (p *GloboDNSProvider) Domains(ctx context.Context) (ds []gdns.Domain, err error) {
	p.clearDomainsCache()

	allDomains, err := p.Domain.List(ctx, &gdns.ListDomainsParameters{PerPage: p.Config.DocumentsPerPage})
	if err != nil {
		return nil, err
	}

	log.Debugf("GloboDNS contains %d domains", len(allDomains))

	for _, d := range allDomains {
		// NOTE: ZoneIDFilter's Match method isn't trustworthy as it matches zone ID by suffix.
		if len(p.Config.ZoneIDFilter.ZoneIDs) > 0 && p.Config.ZoneIDFilter.ZoneIDs[0] != "" && !containsString(p.Config.ZoneIDFilter.ZoneIDs, strconv.Itoa(d.ID)) {
			log.Debugf("Domain (ID: %d, Name: %s) does not match with provided zone ID filter, skipping it", d.ID, d.Name)
			continue
		}

		if p.Config.ZoneFilter.IsConfigured() && !p.Config.ZoneFilter.Match(d.Name) {
			log.Debugf("Domain (ID: %d, Name: %s) does not match with provided zone name filter, skipping it", d.ID, d.Name)
			continue
		}

		log.Debugf("Domain (ID: %d, Name: %s) is able to be managed", d.ID, d.Name)
		ds = append(ds, d)

		p.addDomainInCache(d)
	}

	log.Infof("Handling %d/%d of GloboDNS domains", len(ds), len(allDomains))
	return ds, nil
}

func (p *GloboDNSProvider) createRecords(ctx context.Context, eps []*endpoint.Endpoint) error {
	for _, ep := range eps {
		d, err := p.getDomainFromCache(ep.DNSName)
		if err != nil {
			return err
		}

		for _, r := range newRecord(d, ep) {
			if err := p.createRecord(ctx, d, r); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *GloboDNSProvider) createRecord(ctx context.Context, d *gdns.Domain, r *gdns.Record) error {
	created, err := p.Record.Create(ctx, *r)
	if err != nil {
		return err
	}

	log.Infof("Record (ID: %d, Type: %s, Name: %s, Content: %s, TTL: %s) has been created in %s domain", created.ID, created.Type, created.Name, created.Content, gdns.StringValue(created.TTL), d.Name)
	return nil
}

func (p *GloboDNSProvider) deleteRecords(ctx context.Context, eps []*endpoint.Endpoint) error {
	for _, ep := range eps {
		d, err := p.getDomainFromCache(ep.DNSName)
		if err != nil {
			return err
		}

		for _, r := range newRecord(d, ep) {
			if err = p.deleteRecord(ctx, d, r); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *GloboDNSProvider) deleteRecord(ctx context.Context, d *gdns.Domain, r *gdns.Record) error {
	toRemove, err := p.getRecordByNameAndType(ctx, d.ID, r.Name, r.Type, r.Content)
	if err != nil {
		return err
	}

	err = p.Record.Delete(ctx, toRemove.ID)
	if err != nil {
		return err
	}

	log.Infof("Record (ID: %d, Type: %s, Name: %s, Content: %s, TTL: %s) has been removed from %s domain", toRemove.ID, toRemove.Type, toRemove.Name, toRemove.Content, gdns.StringValue(toRemove.TTL), d.Name)
	return nil
}

func (p *GloboDNSProvider) updateRecords(ctx context.Context, olds, news []*endpoint.Endpoint) error {
	for i := range news {
		oldEP, newEP := olds[i], news[i]

		if oldEP.DNSName != newEP.DNSName {
			return fmt.Errorf("globodns provider does not support changing DNS name (from: %s, to: %s)", oldEP.DNSName, newEP.DNSName)
		}

		if oldEP.RecordType != newEP.RecordType {
			return fmt.Errorf("globodns provider does not support changing record type (from: %s, to: %s)", oldEP.RecordType, newEP.RecordType)
		}

		d, err := p.getDomainFromCache(oldEP.DNSName)
		if err != nil {
			return err
		}

		oldRecords, newRecords := newRecord(d, oldEP), newRecord(d, newEP)

		for _, r := range filterRecordsToCreate(oldRecords, newRecords) {
			if err = p.createRecord(ctx, d, r); err != nil {
				return err
			}
		}

		for _, r := range filterRecordsToRemove(oldRecords, newRecords) {
			if err = p.deleteRecord(ctx, d, r); err != nil {
				return err
			}
		}

		for _, r := range filterRecordsToUpdate(oldRecords, newRecords) {
			if err = p.updateRecord(ctx, d, r); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *GloboDNSProvider) updateRecord(ctx context.Context, d *gdns.Domain, r *gdns.Record) error {
	rr, err := p.getRecordByNameAndType(ctx, d.ID, r.Name, r.Type, r.Content)
	if err != nil {
		return err
	}

	rr.TTL = r.TTL

	if err := p.Record.Update(ctx, *rr); err != nil {
		return err
	}

	log.Infof("Record (ID: %d, Type: %s, Name: %s, Content: %s, TTL: %s) has been updated in %s domain", rr.ID, rr.Type, rr.Name, rr.Content, gdns.StringValue(rr.TTL), d.Name)
	return nil
}

func (p *GloboDNSProvider) getRecordByNameAndType(ctx context.Context, domainID int, name, rtype, content string) (*gdns.Record, error) {
	rs, err := p.Record.List(ctx, domainID, &gdns.ListRecordsParameters{Query: name, PerPage: p.Config.DocumentsPerPage})
	if err != nil {
		return nil, err
	}

	for _, rr := range rs {
		if rr.Name == name && rr.Type == rtype && rr.Content == content {
			return &rr, nil
		}
	}

	return nil, fmt.Errorf("record (name: %v, type: %v, content: %v) does not found", name, rtype, content)
}

func (p *GloboDNSProvider) getDomainFromCache(dnsName string) (*gdns.Domain, error) {
	_, domainName := p.domainsNameByID.FindZone(dnsName)
	if domainName == "" {
		return nil, fmt.Errorf("no suitable domain found")
	}

	d, found := p.domains[domainName]
	if !found {
		return nil, fmt.Errorf("domain %s not found in domains cache", domainName)
	}

	return &d, nil
}

func (p *GloboDNSProvider) clearDomainsCache() {
	p.domains = nil
	p.domainsNameByID = nil
}

func (p *GloboDNSProvider) addDomainInCache(d gdns.Domain) {
	if p.domains == nil {
		p.domains = make(map[string]gdns.Domain)
	}

	p.domains[d.Name] = d

	if p.domainsNameByID == nil {
		p.domainsNameByID = make(provider.ZoneIDName)
	}

	p.domainsNameByID[strconv.Itoa(d.ID)] = d.Name
}

func newEndpoint(d *gdns.Domain, r *gdns.Record) *endpoint.Endpoint {
	dnsName := strings.TrimPrefix(fmt.Sprintf("%s.%s", r.Name, d.Name), "@.") // @.example.com -> example.com
	rtype := strings.ToUpper(r.Type)

	var ttl endpoint.TTL
	if r.TTL != nil && *r.TTL != "" {
		n, err := strconv.Atoi(*r.TTL)
		if err == nil {
			ttl = endpoint.TTL(n)
		} else {
			log.Warnf("could not convert TTL string to integer from record (ID: %d, Name: %s, TTL: %s): %v", r.ID, r.Name, *r.TTL, err)
		}
	}

	return endpoint.NewEndpointWithTTL(dnsName, rtype, ttl, r.Content)
}

func newRecord(d *gdns.Domain, ep *endpoint.Endpoint) []*gdns.Record {
	var ttl *string
	if ep.RecordTTL.IsConfigured() {
		ttl = gdns.StringPointer(strconv.Itoa(int(ep.RecordTTL)))
	}

	name := strings.TrimSuffix(strings.TrimSuffix(ep.DNSName, d.Name), ".")
	if name == "" {
		name = "@"
	}

	var rs []*gdns.Record
	for _, target := range ep.Targets {
		rs = append(rs, &gdns.Record{Name: name, Content: target, Type: strings.ToUpper(ep.RecordType), TTL: ttl, DomainID: d.ID})
	}

	return rs
}

func newHTTPClient(cfg GloboDNSConfig) (*http.Client, error) {
	c := http.DefaultClient

	if cfg.AuthMethod != "oauth" {
		c.Timeout = cfg.RequestTimeout
		return c, nil
	}

	if cfg.OAuthTokenURL == "" {
		return nil, fmt.Errorf("cannot create a GloboDNS client without OAuth token URL")
	}

	if cfg.OAuthClientID == "" {
		return nil, fmt.Errorf("cannot create a GloboDNS client without OAuth client ID")
	}

	if cfg.OAuthClientSecret == "" {
		return nil, fmt.Errorf("cannot create a GloboDNS client without OAuth client secret")
	}

	ocfg := &clientcredentials.Config{
		ClientID:     cfg.OAuthClientID,
		ClientSecret: cfg.OAuthClientSecret,
		TokenURL:     cfg.OAuthTokenURL,
	}
	c = ocfg.Client(context.Background())
	c.Timeout = cfg.RequestTimeout

	return c, nil
}

func containsString(sts []string, s string) bool {
	for _, ss := range sts {
		if ss == s {
			return true
		}
	}

	return false
}

func findRecord(rs []*gdns.Record, r *gdns.Record) (int, bool) {
	for i, rr := range rs {
		if rr.Name == r.Name && rr.Type == r.Type && rr.Content == r.Content {
			return i, true
		}
	}

	return -1, false
}

func filterRecordsToCreate(old, new []*gdns.Record) (rs []*gdns.Record) {
	return filterRecords(new, old, false)
}

func filterRecordsToRemove(old, new []*gdns.Record) (rs []*gdns.Record) {
	return filterRecords(old, new, false)
}

func filterRecordsToUpdate(old, new []*gdns.Record) (rs []*gdns.Record) {
	return filterRecords(new, old, true)
}

func filterRecords(rs1, rs2 []*gdns.Record, should bool) (rs []*gdns.Record) {
	for _, r := range rs1 {
		if _, found := findRecord(rs2, r); found == should {
			rs = append(rs, r)
		}
	}

	return
}
