package controller

import "testing"

func TestFindConflictingEntry(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		entry      string
		existing   []string
		own        []string
		want       string
	}{
		{
			name:       "no existing entries",
			recordType: "A",
			entry:      "10.0.0.1 host.local",
			want:       "",
		},
		{
			name:       "same hostname different IP",
			recordType: "A",
			entry:      "10.0.0.1 host.local",
			existing:   []string{"10.0.0.2 other.local", "10.0.0.9 host.local"},
			want:       "10.0.0.9 host.local",
		},
		{
			name:       "hostname match is case-insensitive",
			recordType: "A",
			entry:      "10.0.0.1 host.local",
			existing:   []string{"10.0.0.9 HOST.local"},
			want:       "10.0.0.9 HOST.local",
		},
		{
			name:       "hostname listed as an alias",
			recordType: "A",
			entry:      "10.0.0.1 host.local",
			existing:   []string{"10.0.0.9 nas.local host.local"},
			want:       "10.0.0.9 nas.local host.local",
		},
		{
			name:       "same hostname same IP is not a conflict",
			recordType: "A",
			entry:      "10.0.0.1 host.local",
			existing:   []string{"10.0.0.1 host.local alias.local"},
			want:       "",
		},
		{
			name:       "AAAA for the same hostname is not a conflict for A",
			recordType: "A",
			entry:      "10.0.0.1 host.local",
			existing:   []string{"fd00::1 host.local"},
			want:       "",
		},
		{
			name:       "AAAA conflicts with another AAAA",
			recordType: "AAAA",
			entry:      "fd00::1 host.local",
			existing:   []string{"10.0.0.1 host.local", "fd00::2 host.local"},
			want:       "fd00::2 host.local",
		},
		{
			name:       "own last-applied entry is ignored",
			recordType: "A",
			entry:      "10.0.0.1 host.local",
			existing:   []string{"10.0.0.9 host.local"},
			own:        []string{"10.0.0.9 host.local"},
			want:       "",
		},
		{
			name:       "suffix match is not a conflict",
			recordType: "A",
			entry:      "10.0.0.1 host.local",
			existing:   []string{"10.0.0.9 myhost.local"},
			want:       "",
		},
		{
			name:       "CNAME alias with different target",
			recordType: "CNAME",
			entry:      "alias.local,target.local",
			existing:   []string{"alias.local,elsewhere.local,300"},
			want:       "alias.local,elsewhere.local,300",
		},
		{
			name:       "CNAME alias with same target and a TTL",
			recordType: "CNAME",
			entry:      "alias.local,target.local",
			existing:   []string{"alias.local,target.local,300"},
			want:       "",
		},
		{
			name:       "CNAME with different alias",
			recordType: "CNAME",
			entry:      "alias.local,target.local",
			existing:   []string{"other.local,elsewhere.local"},
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findConflictingEntry(tt.recordType, tt.entry, tt.existing, tt.own...)
			if got != tt.want {
				t.Errorf("findConflictingEntry() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEntryCoveredBy(t *testing.T) {
	tests := []struct {
		name     string
		entry    string
		existing []string
		want     bool
	}{
		{"exact entry", "10.0.0.1 host.local", []string{"10.0.0.1 host.local"}, true},
		{"hostname as alias on same IP", "10.0.0.1 host.local", []string{"10.0.0.1 nas.local HOST.local"}, true},
		{"same hostname different IP", "10.0.0.1 host.local", []string{"10.0.0.2 host.local"}, false},
		{"same IP different hostname", "10.0.0.1 host.local", []string{"10.0.0.1 other.local"}, false},
		{"no entries", "10.0.0.1 host.local", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := entryCoveredBy(tt.entry, tt.existing); got != tt.want {
				t.Errorf("entryCoveredBy() = %v, want %v", got, tt.want)
			}
		})
	}
}
