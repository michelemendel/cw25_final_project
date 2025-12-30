package main

import "time"

// Config represents the application configuration
type Config struct {
	VulnerabilityTemplates []string `yaml:"vulnerability_templates"`
	VulnerabilityTags      []string `yaml:"vulnerability_tags"`
	Concurrency            int      `yaml:"concurrency"`
	Timeout                string   `yaml:"timeout"`
	OutputDir              string   `yaml:"output_dir"`
	Subfinder              struct {
		UseAllSources bool   `yaml:"use_all_sources"`     // Use -all flag to use all available sources
		Recursive     bool   `yaml:"recursive"`           // Use -recursive flag for recursive discovery
		Active        bool   `yaml:"active"`              // Use -active/-nW flag to only show subdomains that resolve (DNS validation)
		BruteForce    bool   `yaml:"brute_force"`         // Enable brute-force subdomain enumeration
		Wordlist      string `yaml:"wordlist"`            // Path to wordlist file for brute-force
		BruteThreads  int    `yaml:"brute_force_threads"` // Number of threads for brute-force (default: 100)
		ResolversFile string `yaml:"resolvers_file"`      // Path to DNS resolvers file for puredns (optional, will use default if not set)
	} `yaml:"subfinder"`
	Httpx struct {
		FilterStatusCodes string `yaml:"filter_status_codes"` // Filter out status codes (e.g., "404,403,401") - comma separated
	} `yaml:"httpx"`
}

// Scope represents the initial scope for a domain
type Scope struct {
	Domain    string    `json:"domain"`
	Timestamp time.Time `json:"timestamp"`
}

// Subdomain represents a discovered subdomain
type Subdomain struct {
	Source string `json:"source"`
	Name   string `json:"name"`
	Host   string `json:"host"`
}

// LiveHost represents a live web asset
type LiveHost struct {
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Tech       []string `json:"tech"`
	IP         string   `json:"ip"`
	ASN        string   `json:"asn"`
}

// VulnerabilityFinding represents a vulnerability finding
type VulnerabilityFinding struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Classification *struct {
			CVEID       interface{} `json:"cve-id"` // Can be null, string, or array
			CWEID       []string    `json:"cwe-id"`
			CVSSMetrics string      `json:"cvss-metrics"`
		} `json:"classification,omitempty"`
	} `json:"info"`
	Snippet   string `json:"snippet"`
	MatchedAt string `json:"matched-at"`
}
