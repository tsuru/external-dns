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
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gdns "github.com/tsuru/go-globodnsclient"
	globodns "github.com/tsuru/go-globodnsclient"
	"github.com/tsuru/go-globodnsclient/fake"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

var domains = []gdns.Domain{
	{ID: 1, Name: "example.com", TTL: gdns.StringPointer("86400")},
	{ID: 2, Name: "internal.example.com", TTL: gdns.StringPointer("3600")},
	{ID: 3, Name: "example.test", TTL: gdns.StringPointer("60")},
	{ID: 4, Name: "external.example.com"},
	{ID: 5, Name: "tsuru.example.com", TTL: gdns.StringPointer("60")},
	{ID: 6, Name: "tsuru.internal.example.com", TTL: gdns.StringPointer("3600")},
	{ID: 7, Name: "company.internal.example.com", TTL: gdns.StringPointer("3600")},
}

var records = []gdns.Record{
	{DomainID: 1, ID: 1, Name: "www", Type: "A", Content: "169.196.100.100"},
	{DomainID: 1, ID: 2, Name: "@", Type: "MX", Content: "mail"},

	{DomainID: 2, ID: 10, Name: "blog", Type: "A", Content: "169.196.100.101", TTL: gdns.StringPointer("3600")},
	{DomainID: 2, ID: 11, Name: "readme", Type: "CNAME", Content: "blog", TTL: gdns.StringPointer("0")},
	{DomainID: 2, ID: 12, Name: "blog", Type: "TXT", Content: "foo=bar,bar=baz"},

	{DomainID: 4, ID: 40001, Name: "@", Type: "NS", Content: "ns01.external.test"},

	{DomainID: 6, ID: 60001, Name: "app1.apps", Type: "A", Content: "169.196.100.254", TTL: gdns.StringPointer("300")},
	{DomainID: 6, ID: 60002, Name: "app1.apps", Type: "TXT", Content: `"heritage=external-dns,external-dns/owner=my-cluster-id,external-dns/resource=service/default/app1"`, TTL: gdns.StringPointer("300")},
	{DomainID: 6, ID: 60003, Name: "app2.apps", Type: "A", Content: "169.254.254.200", TTL: gdns.StringPointer("30")},
	{DomainID: 6, ID: 60004, Name: "app2.apps", Type: "A", Content: "169.254.254.201", TTL: gdns.StringPointer("30")},

	{DomainID: 7, ID: 70001, Name: "my-server", Type: "A", Content: "169.254.254.200"},
	{DomainID: 7, ID: 70002, Name: "my-server", Type: "A", Content: "169.254.254.201"},
	{DomainID: 7, ID: 70003, Name: "my-server", Type: "A", Content: "169.254.254.202"},
}

func TestNew(t *testing.T) {
	tests := map[string]struct {
		cfg           GloboDNSConfig
		expectedError string
	}{
		"using oauth as auth method, passing no token URL": {
			cfg: GloboDNSConfig{
				AuthMethod: "oauth",
			},
			expectedError: "cannot create a GloboDNS client without OAuth token URL",
		},

		"using oauth as auth method, passing no client ID": {
			cfg: GloboDNSConfig{
				AuthMethod:    "oauth",
				OAuthTokenURL: "https://id.example.com/token",
			},
			expectedError: "cannot create a GloboDNS client without OAuth client ID",
		},

		"using oauth as auth method, passing no client secret": {
			cfg: GloboDNSConfig{
				AuthMethod:    "oauth",
				OAuthTokenURL: "https://id.example.com/token",
				OAuthClientID: "my-client-id",
			},
			expectedError: "cannot create a GloboDNS client without OAuth client secret",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewGloboDNSProvider(tt.cfg)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestGloboDNSProvider_Records(t *testing.T) {
	tests := map[string]struct {
		zoneFilter endpoint.DomainFilter
		client     *gdns.Client
		expected   []*endpoint.Endpoint
	}{
		"listing supported records from .example.com": {
			zoneFilter: endpoint.NewDomainFilter([]string{"example.com"}),
			client: &gdns.Client{
				Domain: &fake.FakeDomainService{
					FakeList: func(ctx context.Context, _ *gdns.ListDomainsParameters) ([]gdns.Domain, error) {
						return domains, nil
					},
				},
				Record: &fake.FakeRecordService{
					FakeList: func(ctx context.Context, domainID int, _ *gdns.ListRecordsParameters) ([]gdns.Record, error) {
						return listRecordsByDomainID(domainID), nil
					},
				},
			},
			expected: []*endpoint.Endpoint{
				{DNSName: "app1.apps.tsuru.internal.example.com", RecordType: "A", Targets: endpoint.NewTargets("169.196.100.254"), RecordTTL: endpoint.TTL(300), Labels: endpoint.NewLabels()},
				{DNSName: "app1.apps.tsuru.internal.example.com", RecordType: "TXT", Targets: endpoint.NewTargets(`"heritage=external-dns,external-dns/owner=my-cluster-id,external-dns/resource=service/default/app1"`), RecordTTL: endpoint.TTL(300), Labels: endpoint.NewLabels()},
				{DNSName: "app2.apps.tsuru.internal.example.com", RecordType: "A", RecordTTL: endpoint.TTL(30), Targets: endpoint.NewTargets("169.254.254.200", "169.254.254.201"), Labels: endpoint.NewLabels()},
				{DNSName: "blog.internal.example.com", RecordType: "A", RecordTTL: endpoint.TTL(3600), Targets: endpoint.NewTargets("169.196.100.101"), Labels: endpoint.NewLabels()},
				{DNSName: "blog.internal.example.com", RecordType: "TXT", Targets: endpoint.NewTargets("foo=bar,bar=baz"), Labels: endpoint.NewLabels()},
				{DNSName: "external.example.com", RecordType: "NS", Targets: endpoint.NewTargets("ns01.external.test"), Labels: endpoint.NewLabels()},
				{DNSName: "my-server.company.internal.example.com", RecordType: "A", Targets: endpoint.NewTargets("169.254.254.200", "169.254.254.201", "169.254.254.202"), Labels: endpoint.NewLabels()},
				{DNSName: "readme.internal.example.com", RecordType: "CNAME", Targets: endpoint.NewTargets("blog"), Labels: endpoint.NewLabels()},
				{DNSName: "www.example.com", RecordType: "A", Targets: endpoint.NewTargets("169.196.100.100"), Labels: endpoint.NewLabels()},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := NewGloboDNSProviderWithClient(tt.client, GloboDNSConfig{
				ZoneFilter: tt.zoneFilter,
			})
			require.NoError(t, err)

			got, err := p.Records(context.TODO())
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestGloboDNSProvider_Domains(t *testing.T) {
	tests := map[string]struct {
		cfg      GloboDNSConfig
		expected []gdns.Domain
	}{
		"without zone filter, should return all domains": {
			expected: domains,
		},

		"with zone filter == internal.example.com": {
			cfg: GloboDNSConfig{
				ZoneFilter: endpoint.NewDomainFilter([]string{"internal.example.com"}),
			},
			expected: []gdns.Domain{
				{ID: 2, Name: "internal.example.com", TTL: gdns.StringPointer("3600")},
				{ID: 6, Name: "tsuru.internal.example.com", TTL: gdns.StringPointer("3600")},
				{ID: 7, Name: "company.internal.example.com", TTL: gdns.StringPointer("3600")},
			},
		},

		"with zone ID filter == 5 or 7": {
			cfg: GloboDNSConfig{
				ZoneIDFilter: provider.NewZoneIDFilter([]string{"5", "7"}),
			},
			expected: []gdns.Domain{
				{ID: 5, Name: "tsuru.example.com", TTL: gdns.StringPointer("60")},
				{ID: 7, Name: "company.internal.example.com", TTL: gdns.StringPointer("3600")},
			},
		},

		"with zone ID and name filters": {
			cfg: GloboDNSConfig{
				ZoneIDFilter: provider.NewZoneIDFilter([]string{"5", "7"}),
				ZoneFilter:   endpoint.NewDomainFilter([]string{"internal.example.com"}),
			},
			expected: []gdns.Domain{
				{ID: 7, Name: "company.internal.example.com", TTL: gdns.StringPointer("3600")},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			client := fake.New()
			client.Domain = &fake.FakeDomainService{
				FakeList: func(ctx context.Context, p *gdns.ListDomainsParameters) ([]gdns.Domain, error) {
					return domains, nil
				},
			}

			p, err := NewGloboDNSProviderWithClient(client, tt.cfg)
			require.NoError(t, err)

			globoDNSProvider, ok := p.(*GloboDNSProvider)
			require.True(t, ok)

			got, err := globoDNSProvider.Domains(context.TODO())
			require.NoError(t, err)

			assert.Equal(t, tt.expected, got)
			require.NotNil(t, globoDNSProvider.domains)
			require.NotNil(t, globoDNSProvider.domainsNameByID)

			for _, d := range got {
				dd, found := globoDNSProvider.domains[d.Name]
				assert.True(t, found)
				assert.Equal(t, dd, d)

				domain, found := globoDNSProvider.domainsNameByID[strconv.Itoa(d.ID)]
				assert.True(t, found)
				assert.Equal(t, d.Name, domain)
			}
		})
	}
}

func TestGloboDNSProvider_ApplyChanges(t *testing.T) {
	var count int

	tests := map[string]struct {
		changes       *plan.Changes
		client        *gdns.Client
		expectedError string
		expectedCount int
	}{
		"creating records on GloboDNS": {
			changes: &plan.Changes{
				Create: []*endpoint.Endpoint{
					{RecordType: "A", DNSName: "svc-1.internal.example.com", Targets: endpoint.NewTargets("169.196.100.100")},
					{RecordType: "TXT", DNSName: "svc-1.internal.example.com", Targets: endpoint.NewTargets(`"heritage=external-dns,external-dns/owner=my-cluster-id,external-dns/resource=service/default/svc-1"`)},
					{RecordType: "A", DNSName: "internal.example.com", Targets: endpoint.NewTargets("169.196.100.101"), RecordTTL: endpoint.TTL(60)},
				},
			},
			client: &gdns.Client{
				Record: &fake.FakeRecordService{
					FakeCreate: func(ctx context.Context, r gdns.Record) (*gdns.Record, error) {
						defer func() { count++ }()

						if count == 0 {
							assert.Equal(t, gdns.Record{Name: "svc-1", Content: "169.196.100.100", Type: "A", DomainID: 2}, r)
							return &r, nil
						}

						if count == 1 {
							assert.Equal(t, gdns.Record{Name: "svc-1", Content: `"heritage=external-dns,external-dns/owner=my-cluster-id,external-dns/resource=service/default/svc-1"`, Type: "TXT", DomainID: 2}, r)
							return &r, nil
						}

						if count == 2 {
							assert.Equal(t, gdns.Record{Name: "@", Content: "169.196.100.101", Type: "A", TTL: gdns.StringPointer("60"), DomainID: 2}, r)
							return &r, nil
						}

						return nil, fmt.Errorf("should not pass here")
					},
				},
				Bind: &fake.FakeBindService{
					FakeExport: func(ctx context.Context) (*gdns.ScheduleExport, error) {
						defer func() { count++ }()

						if count == 3 {
							return &gdns.ScheduleExport{
								Output:       "BIND export scheduled for 01 Nov 14:00",
								ScheduleDate: time.Date(2021, 11, 1, 14, 0, 0, 0, time.UTC),
							}, nil
						}

						return nil, fmt.Errorf("should not pass here")
					},
				},
			},
			expectedCount: 4,
		},

		"creating records from endpoint with multiple targets": {
			changes: &plan.Changes{
				Create: []*endpoint.Endpoint{
					{RecordType: "A", DNSName: "multiple.targets.internal.example.com", Targets: endpoint.NewTargets("169.254.254.250", "169.254.254.251", "169.254.254.252")},
				},
			},
			client: &gdns.Client{
				Record: &fake.FakeRecordService{
					FakeCreate: func(ctx context.Context, r gdns.Record) (*gdns.Record, error) {
						defer func() { count++ }()

						if count == 0 {
							assert.Equal(t, gdns.Record{Name: "multiple.targets", Content: "169.254.254.250", Type: "A", DomainID: 2}, r)
							return &r, nil
						}

						if count == 1 {
							assert.Equal(t, gdns.Record{Name: "multiple.targets", Content: "169.254.254.251", Type: "A", DomainID: 2}, r)
							return &r, nil
						}

						if count == 2 {
							assert.Equal(t, gdns.Record{Name: "multiple.targets", Content: "169.254.254.252", Type: "A", DomainID: 2}, r)
							return &r, nil
						}

						return nil, fmt.Errorf("should not pass here")
					},
				},
				Bind: &fake.FakeBindService{
					FakeExport: func(ctx context.Context) (*gdns.ScheduleExport, error) {
						defer func() { count++ }()

						if count == 3 {
							return &gdns.ScheduleExport{
								Output:       "BIND export scheduled for 01 Nov 14:00",
								ScheduleDate: time.Date(2021, 11, 1, 14, 0, 0, 0, time.UTC),
							}, nil
						}

						return nil, fmt.Errorf("should not pass here")
					},
				},
			},
			expectedCount: 4,
		},

		"removing records on GloboDNS": {
			changes: &plan.Changes{
				Delete: []*endpoint.Endpoint{
					{RecordType: "A", DNSName: "app1.apps.tsuru.internal.example.com", Targets: endpoint.NewTargets("169.196.100.254"), RecordTTL: endpoint.TTL(300)},
					{RecordType: "TXT", DNSName: "app1.apps.tsuru.internal.example.com", Targets: endpoint.NewTargets(`"heritage=external-dns,external-dns/owner=my-cluster-id,external-dns/resource=service/default/app1"`), RecordTTL: endpoint.TTL(300)},
				},
			},
			client: &gdns.Client{
				Record: &fake.FakeRecordService{
					FakeList: func(ctx context.Context, domainID int, p *gdns.ListRecordsParameters) ([]gdns.Record, error) {
						defer func() { count++ }()

						if count == 0 || count == 2 {
							assert.Equal(t, 6, domainID)
							require.NotNil(t, p)
							assert.Equal(t, "app1.apps", p.Query)
							return listRecordsByDomainID(6), nil
						}

						return nil, fmt.Errorf("should not pass here")
					},
					FakeDelete: func(ctx context.Context, recordID int) error {
						defer func() { count++ }()

						if count == 1 {
							assert.Equal(t, 60001, recordID)
							return nil
						}

						if count == 3 {
							assert.Equal(t, 60002, recordID)
							return nil
						}

						return fmt.Errorf("should not pass here")
					},
				},
				Bind: &fake.FakeBindService{
					FakeExport: func(ctx context.Context) (*gdns.ScheduleExport, error) {
						defer func() { count++ }()

						if count == 4 {
							return &gdns.ScheduleExport{
								Output:       "BIND export scheduled for 01 Nov 14:00",
								ScheduleDate: time.Date(2021, 11, 1, 14, 0, 0, 0, time.UTC),
							}, nil
						}

						return nil, fmt.Errorf("should not pass here")
					},
				},
			},
			expectedCount: 5,
		},

		"removing records from endpoint with multiple targets": {
			changes: &plan.Changes{
				Delete: []*endpoint.Endpoint{
					{RecordType: "A", DNSName: "app2.apps.tsuru.internal.example.com", Targets: endpoint.NewTargets("169.254.254.200", "169.254.254.201"), RecordTTL: endpoint.TTL(300)},
				},
			},
			client: &gdns.Client{
				Record: &fake.FakeRecordService{
					FakeList: func(ctx context.Context, domainID int, p *gdns.ListRecordsParameters) ([]gdns.Record, error) {
						defer func() { count++ }()

						if count == 0 || count == 2 {
							assert.Equal(t, 6, domainID)
							require.NotNil(t, p)
							assert.Equal(t, "app2.apps", p.Query)
							return listRecordsByDomainID(6), nil
						}

						return nil, fmt.Errorf("should not pass here")
					},
					FakeDelete: func(ctx context.Context, recordID int) error {
						defer func() { count++ }()

						if count == 1 {
							assert.Equal(t, 60003, recordID)
							return nil
						}

						if count == 3 {
							assert.Equal(t, 60004, recordID)
							return nil
						}

						return fmt.Errorf("should not pass here")
					},
				},
				Bind: &fake.FakeBindService{
					FakeExport: func(ctx context.Context) (*gdns.ScheduleExport, error) {
						defer func() { count++ }()

						if count == 4 {
							return &gdns.ScheduleExport{
								Output:       "BIND export scheduled for 01 Nov 14:00",
								ScheduleDate: time.Date(2021, 11, 1, 14, 0, 0, 0, time.UTC),
							}, nil
						}

						return nil, fmt.Errorf("should not pass here")
					},
				},
			},
			expectedCount: 5,
		},

		"updating record's name": {
			changes: &plan.Changes{
				UpdateOld: []*endpoint.Endpoint{{DNSName: "app1.example.com"}},
				UpdateNew: []*endpoint.Endpoint{{DNSName: "new-app.example.com"}},
			},
			expectedError: "globodns provider does not support changing DNS name (from: app1.example.com, to: new-app.example.com)",
		},

		"updating record's type": {
			changes: &plan.Changes{
				UpdateOld: []*endpoint.Endpoint{{RecordType: "A"}},
				UpdateNew: []*endpoint.Endpoint{{RecordType: "AAAA"}},
			},
			expectedError: "globodns provider does not support changing record type (from: A, to: AAAA)",
		},

		"updating records on GloboDNS": {
			changes: &plan.Changes{
				UpdateOld: []*endpoint.Endpoint{
					{RecordType: "A", DNSName: "app1.apps.tsuru.internal.example.com", Targets: endpoint.NewTargets("169.196.100.254"), RecordTTL: endpoint.TTL(300)},
				},
				UpdateNew: []*endpoint.Endpoint{
					{RecordType: "A", DNSName: "app1.apps.tsuru.internal.example.com", Targets: endpoint.NewTargets("169.196.100.254"), RecordTTL: endpoint.TTL(10)},
				},
			},
			client: &gdns.Client{
				Record: &fake.FakeRecordService{
					FakeList: func(ctx context.Context, domainID int, p *gdns.ListRecordsParameters) ([]gdns.Record, error) {
						defer func() { count++ }()

						if count == 0 {
							assert.Equal(t, 6, domainID)
							require.NotNil(t, p)
							assert.Equal(t, "app1.apps", p.Query)
							return listRecordsByDomainID(6), nil
						}

						return nil, fmt.Errorf("should not pass here")
					},

					FakeUpdate: func(ctx context.Context, r gdns.Record) error {
						defer func() { count++ }()

						if count == 1 {
							assert.Equal(t, gdns.Record{DomainID: 6, ID: 60001, Name: "app1.apps", Type: "A", Content: "169.196.100.254", TTL: gdns.StringPointer("10")}, r)
							return nil
						}

						return fmt.Errorf("should not pass here")
					},
				},
				Bind: &fake.FakeBindService{
					FakeExport: func(ctx context.Context) (*gdns.ScheduleExport, error) {
						defer func() { count++ }()

						if count == 2 {
							return &gdns.ScheduleExport{
								Output:       "BIND export scheduled for 01 Nov 14:00",
								ScheduleDate: time.Date(2021, 11, 1, 14, 0, 0, 0, time.UTC),
							}, nil
						}

						return nil, fmt.Errorf("should not pass here")
					},
				},
			},
			expectedCount: 3,
		},

		"updating records from endpoint with multiple targets": {
			changes: &plan.Changes{
				UpdateOld: []*endpoint.Endpoint{
					{RecordType: "A", DNSName: "app2.apps.tsuru.internal.example.com", Targets: endpoint.NewTargets("169.254.254.200", "169.254.254.201"), RecordTTL: endpoint.TTL(30)},
				},
				UpdateNew: []*endpoint.Endpoint{
					{RecordType: "A", DNSName: "app2.apps.tsuru.internal.example.com", Targets: endpoint.NewTargets("169.254.254.200", "169.254.254.202"), RecordTTL: endpoint.TTL(10)},
				},
			},
			client: &gdns.Client{
				Record: &fake.FakeRecordService{
					FakeCreate: func(ctx context.Context, r globodns.Record) (*globodns.Record, error) {
						defer func() { count++ }()

						if count == 0 {
							assert.Equal(t, globodns.Record{Name: "app2.apps", Type: "A", Content: "169.254.254.202", TTL: globodns.StringPointer("10"), DomainID: 6}, r)
							return &gdns.Record{}, nil
						}

						return nil, fmt.Errorf("should not pass here")
					},

					FakeDelete: func(ctx context.Context, recordID int) error {
						defer func() { count++ }()

						if count == 2 {
							assert.Equal(t, 60004, recordID)
							return nil
						}

						return fmt.Errorf("should not pass here")
					},

					FakeList: func(ctx context.Context, domainID int, p *gdns.ListRecordsParameters) ([]gdns.Record, error) {
						defer func() { count++ }()

						if count == 1 {
							assert.Equal(t, 6, domainID)
							assert.Equal(t, &gdns.ListRecordsParameters{Query: "app2.apps"}, p)
							return listRecordsByDomainID(6), nil
						}

						if count == 3 {
							assert.Equal(t, 6, domainID)
							assert.Equal(t, &gdns.ListRecordsParameters{Query: "app2.apps"}, p)
							return listRecordsByDomainID(6), nil
						}

						return nil, fmt.Errorf("should not pass here")
					},

					FakeUpdate: func(ctx context.Context, r gdns.Record) error {
						defer func() { count++ }()

						if count == 4 {
							assert.Equal(t, gdns.Record{DomainID: 6, ID: 60003, Name: "app2.apps", Type: "A", Content: "169.254.254.200", TTL: gdns.StringPointer("10")}, r)
							return nil
						}

						return fmt.Errorf("should not pass")
					},
				},

				Bind: &fake.FakeBindService{
					FakeExport: func(ctx context.Context) (*gdns.ScheduleExport, error) {
						defer func() { count++ }()

						if count == 5 {
							return &gdns.ScheduleExport{
								Output:       "BIND export scheduled for 01 Nov 14:00",
								ScheduleDate: time.Date(2021, 11, 1, 14, 0, 0, 0, time.UTC),
							}, nil
						}

						return nil, fmt.Errorf("should not pass here")
					},
				},
			},
			expectedCount: 6,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			count = 0
			err := newGloboDNSProvider(tt.client).ApplyChanges(context.TODO(), tt.changes)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCount, count)
		})
	}
}

func listRecordsByDomainID(id int) (rs []gdns.Record) {
	for _, r := range records {
		if r.DomainID != id {
			continue
		}

		rs = append(rs, r)
	}

	return
}

func newGloboDNSProvider(c *gdns.Client) *GloboDNSProvider {
	p := &GloboDNSProvider{Client: c, Config: &GloboDNSConfig{}}

	for _, d := range domains {
		p.addDomainInCache(d)
	}

	return p
}
