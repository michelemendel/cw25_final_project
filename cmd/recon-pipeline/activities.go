package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

type Activities struct {
	Config *Config
}

func (a *Activities) ParseScope(ctx context.Context, domain string) error {
	log.Printf("%s: ParseScope: Starting...", domain)
	outDir := filepath.Join(a.Config.OutputDir, domain)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	scope := []Scope{
		{
			Domain:    domain,
			Timestamp: time.Now(),
		},
	}

	scopeFile := filepath.Join(outDir, "scope.json")
	f, err := os.Create(scopeFile)
	if err != nil {
		return fmt.Errorf("failed to create scope file: %w", err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(scope); err != nil {
		return fmt.Errorf("failed to write scope file: %w", err)
	}

	log.Printf("%s: ParseScope: Completed", domain)
	return nil
}

func (a *Activities) DiscoverSubdomains(ctx context.Context, domain string) error {
	log.Printf("%s: DiscoverSubdomains: Starting...", domain)
	outDir := filepath.Join(a.Config.OutputDir, domain)
	outputFile := filepath.Join(outDir, "subdomains.jsonl")

	// Check if file exists and remove it to avoid appending duplicates if retrying
	os.Remove(outputFile)

	var allSubdomains []Subdomain

	// Step 1: Run Subfinder (passive enumeration)
	subfinderFile := filepath.Join(outDir, "subdomains_subfinder.jsonl")
	args := []string{"-d", domain, "-json", "-o", subfinderFile}
	if a.Config.Subfinder.UseAllSources {
		args = append(args, "-all")
	}
	if a.Config.Subfinder.Recursive {
		args = append(args, "-recursive")
	}
	if a.Config.Subfinder.Active {
		args = append(args, "-active")
	}
	cmd := exec.CommandContext(ctx, "subfinder", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Printf("%s: Subfinder failed: %v, stderr: %s", domain, err, stderr.String())
		// Don't fail completely, continue with brute-force if enabled
	} else {
		// Read subfinder results
		if subdomains, err := readSubdomainsFromFile(subfinderFile); err == nil {
			allSubdomains = append(allSubdomains, subdomains...)
			log.Printf("%s: Subfinder found %d subdomains", domain, len(subdomains))
		}
	}

	// Step 2: Run brute-force if enabled
	if a.Config.Subfinder.BruteForce && a.Config.Subfinder.Wordlist != "" {
		bruteForceFile := filepath.Join(outDir, "subdomains_bruteforce.jsonl")
		if err := a.runBruteForce(ctx, domain, bruteForceFile); err != nil {
			log.Printf("%s: Brute-force failed: %v (continuing with existing results)", domain, err)
		} else {
			// Read brute-force results
			if subdomains, err := readSubdomainsFromFile(bruteForceFile); err == nil {
				allSubdomains = append(allSubdomains, subdomains...)
				log.Printf("%s: Brute-force found %d subdomains", domain, len(subdomains))
			}
		}
	}

	// Step 3: Deduplicate and merge results
	uniqueSubdomains := deduplicateSubdomains(allSubdomains)

	// Step 4: Write merged results to output file
	if err := writeSubdomainsToFile(outputFile, uniqueSubdomains); err != nil {
		return fmt.Errorf("failed to write subdomains: %w", err)
	}

	// Count final subdomains found
	if count, err := countSubdomains(outputFile); err == nil {
		log.Printf("%s: DiscoverSubdomains: Completed - found %d unique subdomains", domain, count)
	} else {
		log.Printf("%s: DiscoverSubdomains: Completed - found %d unique subdomains", domain, len(uniqueSubdomains))
	}

	return nil
}

// runBruteForce runs brute-force subdomain enumeration using puredns
func (a *Activities) runBruteForce(ctx context.Context, domain, outputFile string) error {
	wordlist := a.Config.Subfinder.Wordlist
	if wordlist == "" {
		return fmt.Errorf("wordlist path not configured")
	}

	// Check if wordlist file exists
	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		return fmt.Errorf("wordlist file not found: %s", wordlist)
	}

	// Check if massdns is available (required by puredns)
	if _, err := exec.LookPath("massdns"); err != nil {
		return fmt.Errorf("massdns not found in PATH (required by puredns). Install with: brew install massdns (macOS) or build from source (Linux)")
	}

	// Ensure resolvers file exists
	resolversFile, err := a.ensureResolversFile()
	if err != nil {
		return fmt.Errorf("failed to setup resolvers file: %w", err)
	}

	threads := a.Config.Subfinder.BruteThreads
	if threads <= 0 {
		threads = 100 // Default
	}

	// puredns outputs plain text, so we'll write to a temp file and convert to JSONL
	tempFile := outputFile + ".tmp"

	// Use puredns for brute-force
	args := []string{
		"bruteforce",
		wordlist,
		domain,
		"-w", tempFile,
		"-t", fmt.Sprintf("%d", threads),
		"-r", resolversFile, // Specify resolvers file
		"--quiet", // Reduce output noise
	}

	cmd := exec.CommandContext(ctx, "puredns", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// puredns may exit with non-zero if no subdomains found, which is OK
		// Check if output file was created
		if _, statErr := os.Stat(tempFile); statErr != nil {
			return fmt.Errorf("puredns failed: %v, stderr: %s", err, stderr.String())
		}
		// File exists, so some results may have been found
	}

	// Convert plain text output to JSONL format
	if err := convertPurednsOutputToJSONL(tempFile, outputFile, domain); err != nil {
		// Clean up temp file
		os.Remove(tempFile)
		return fmt.Errorf("failed to convert puredns output: %w", err)
	}

	// Clean up temp file
	os.Remove(tempFile)
	return nil
}

// ensureResolversFile ensures the puredns resolvers file exists, creating it if necessary
func (a *Activities) ensureResolversFile() (string, error) {
	// If user specified a custom resolvers file, use it
	if a.Config.Subfinder.ResolversFile != "" {
		if _, err := os.Stat(a.Config.Subfinder.ResolversFile); err == nil {
			return a.Config.Subfinder.ResolversFile, nil
		}
		return "", fmt.Errorf("specified resolvers file not found: %s", a.Config.Subfinder.ResolversFile)
	}

	// Use default puredns location
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	resolversDir := filepath.Join(homeDir, ".config", "puredns")
	resolversFile := filepath.Join(resolversDir, "resolvers.txt")

	// Check if file already exists
	if _, err := os.Stat(resolversFile); err == nil {
		return resolversFile, nil
	}

	// File doesn't exist, create directory and generate resolvers
	log.Printf("Resolvers file not found at %s, generating trusted resolvers...", resolversFile)
	if err := os.MkdirAll(resolversDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create puredns config directory: %w", err)
	}

	// Use puredns to generate trusted resolvers
	// puredns resolve --help shows: "resolve" command can generate trusted resolvers
	// We'll use a common public resolvers list as fallback
	if err := a.generateResolversFile(resolversFile); err != nil {
		return "", fmt.Errorf("failed to generate resolvers file: %w", err)
	}

	log.Printf("Generated resolvers file at %s", resolversFile)
	return resolversFile, nil
}

// generateResolversFile generates a resolvers file with trusted public DNS resolvers
func (a *Activities) generateResolversFile(resolversFile string) error {
	// Create a file with common trusted public DNS resolvers
	// These are well-known public DNS servers
	trustedResolvers := []string{
		"1.1.1.1",         // Cloudflare
		"1.0.0.1",         // Cloudflare
		"8.8.8.8",         // Google
		"8.8.4.4",         // Google
		"9.9.9.9",         // Quad9
		"149.112.112.112", // Quad9
		"208.67.222.222",  // OpenDNS
		"208.67.220.220",  // OpenDNS
		"76.76.19.19",     // Alternate DNS
		"76.223.122.150",  // Alternate DNS
	}

	f, err := os.Create(resolversFile)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, resolver := range trustedResolvers {
		if _, err := fmt.Fprintln(f, resolver); err != nil {
			return err
		}
	}

	return nil
}

// convertPurednsOutputToJSONL converts puredns plain text output to JSONL format
func convertPurednsOutputToJSONL(inputFile, outputFile, domain string) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		if os.IsNotExist(err) {
			// No results found, create empty output file
			os.Create(outputFile)
			return nil
		}
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	encoder := json.NewEncoder(outFile)
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		hostname := strings.TrimSpace(scanner.Text())
		if hostname == "" {
			continue
		}
		// Create Subdomain struct matching subfinder format
		sub := Subdomain{
			Host:   hostname,
			Name:   hostname,
			Source: "bruteforce",
		}
		if err := encoder.Encode(sub); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// readSubdomainsFromFile reads subdomains from a JSONL file
func readSubdomainsFromFile(filename string) ([]Subdomain, error) {
	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return []Subdomain{}, nil // File doesn't exist, return empty slice
		}
		return nil, err
	}
	defer f.Close()

	var subdomains []Subdomain
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var sub Subdomain
		if err := json.Unmarshal(scanner.Bytes(), &sub); err == nil {
			// Normalize: use Host if available, otherwise Name
			if sub.Host == "" && sub.Name != "" {
				sub.Host = sub.Name
			}
			if sub.Host != "" {
				subdomains = append(subdomains, sub)
			}
		}
	}
	return subdomains, scanner.Err()
}

// deduplicateSubdomains removes duplicate subdomains based on hostname
func deduplicateSubdomains(subdomains []Subdomain) []Subdomain {
	seen := make(map[string]bool)
	var unique []Subdomain

	for _, sub := range subdomains {
		host := sub.Host
		if host == "" {
			host = sub.Name
		}
		if host != "" && !seen[host] {
			seen[host] = true
			unique = append(unique, sub)
		}
	}

	return unique
}

// writeSubdomainsToFile writes subdomains to a JSONL file
func writeSubdomainsToFile(filename string, subdomains []Subdomain) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	for _, sub := range subdomains {
		if err := encoder.Encode(sub); err != nil {
			return err
		}
	}
	return nil
}

// countSubdomains counts the number of subdomains in a JSONL file
func countSubdomains(filename string) (int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}

// countLiveHosts counts the number of live hosts in a JSONL file
func countLiveHosts(filename string) (int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}

// countVulnerabilityFindings counts the number of findings in a JSONL file
func countVulnerabilityFindings(filename string) (int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}

func (a *Activities) IdentifyLiveHosts(ctx context.Context, domain string) error {
	outDir := filepath.Join(a.Config.OutputDir, domain)
	subdomainsFile := filepath.Join(outDir, "subdomains.jsonl")
	outputFile := filepath.Join(outDir, "live_hosts.jsonl")

	// Check if subdomains file exists
	if _, err := os.Stat(subdomainsFile); os.IsNotExist(err) {
		return fmt.Errorf("subdomains file not found: %s", subdomainsFile)
	}

	// Liveness check needs stdin or list input. We'll use the file and pipe it carefully.
	// However, the subdomains file is JSONL. We need to extract the hostnames.
	// A robust way is to read the file, extract domains, and pass to stdin.

	file, err := os.Open(subdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to open subdomains file: %w", err)
	}
	defer file.Close()

	var domains []string
	domainSet := make(map[string]bool) // Track unique domains
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var sub Subdomain
		if err := json.Unmarshal(scanner.Bytes(), &sub); err != nil {
			continue
		}
		hostname := ""
		if sub.Host != "" {
			hostname = sub.Host
		} else if sub.Name != "" {
			hostname = sub.Name
		}
		if hostname != "" && !domainSet[hostname] {
			domains = append(domains, hostname)
			domainSet[hostname] = true
		}
	}
	
	// Always include the root domain itself (if not already in the list)
	if !domainSet[domain] {
		domains = append(domains, domain)
		domainSet[domain] = true
		log.Printf("%s: IdentifyLiveHosts: Added root domain to scan list", domain)
	}
	
	log.Printf("%s: IdentifyLiveHosts: Found %d domains (including root domain)", domain, len(domains))

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading subdomains file: %w", err)
	}

	if len(domains) == 0 {
		log.Printf("%s: IdentifyLiveHosts: No domains found - skipping scan", domain)
		// Create empty live_hosts.jsonl file to indicate no live hosts found
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create empty live hosts file: %w", err)
		}
		f.Close()
		log.Printf("%s: IdentifyLiveHosts: Completed - no subdomains to scan", domain)
		return nil
	}

	log.Printf("%s: IdentifyLiveHosts: Starting scan (%d domains)...", domain, len(domains))
	// Prepare liveness check command
	args := []string{"-json", "-o", outputFile}
	// Add status code filter if configured
	if a.Config.Httpx.FilterStatusCodes != "" {
		args = append(args, "-fc", a.Config.Httpx.FilterStatusCodes)
	}
	cmd := exec.CommandContext(ctx, "httpx", args...)

	// Create a pipe for stdin
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start liveness check: %w", err)
	}

	// Write domains to stdin
	go func() {
		defer stdin.Close()
		for _, d := range domains {
			if d != "" {
				fmt.Fprintln(stdin, d)
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		// Check if the output file was created and has content
		// Liveness check tool may exit with non-zero if no live hosts are found, but that's still a valid result
		if info, statErr := os.Stat(outputFile); statErr == nil && info.Size() > 0 {
			// File exists and has content, so liveness check succeeded even with non-zero exit
			log.Printf("%s: IdentifyLiveHosts: Exited with error but produced output (this is normal if some hosts are unreachable)", domain)
			// Count live hosts found
			if count, err := countLiveHosts(outputFile); err == nil {
				log.Printf("%s: IdentifyLiveHosts: Completed - found %d live hosts", domain, count)
			}
			return nil
		}
		// If file is empty or doesn't exist, check if it's because no hosts were found
		if info, statErr := os.Stat(outputFile); statErr == nil && info.Size() == 0 {
			log.Printf("%s: IdentifyLiveHosts: Completed - no live hosts found", domain)
			return nil // Empty file is a valid result (no live hosts)
		}
		// Otherwise, it's a real error
		log.Printf("%s: IdentifyLiveHosts: Failed - %v, stderr: %s", domain, err, stderr.String())
		return fmt.Errorf("liveness check failed: %v, stderr: %s", err, stderr.String())
	}

	// liveness check completed successfully
	if count, err := countLiveHosts(outputFile); err == nil {
		log.Printf("%s: IdentifyLiveHosts: Completed - found %d live hosts", domain, count)
	} else {
		log.Printf("%s: IdentifyLiveHosts: Completed", domain)
	}

	return nil
}

func (a *Activities) ScanVulnerabilities(ctx context.Context, domain string) error {
	outDir := filepath.Join(a.Config.OutputDir, domain)
	liveHostsFile := filepath.Join(outDir, "live_hosts.jsonl")
	outputFile := filepath.Join(outDir, "vulnerability_findings.jsonl")

	log.Printf("%s: ScanVulnerabilities: Starting...", domain)

	// Extract URLs from live_hosts.jsonl
	file, err := os.Open(liveHostsFile)
	if err != nil {
		return fmt.Errorf("failed to open live hosts file: %w", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var host LiveHost
		if err := json.Unmarshal(scanner.Bytes(), &host); err == nil {
			if host.URL != "" {
				urls = append(urls, host.URL)
			}
		}
	}

	if len(urls) == 0 {
		// No live hosts, skip vulnerability scan
		log.Printf("%s: ScanVulnerabilities: Skipping - no live hosts found", domain)
		return nil
	}

	log.Printf("%s: ScanVulnerabilities: Found %d live hosts to scan", domain, len(urls))

	targetsFile := filepath.Join(outDir, "vulnerability_targets_temp.txt")
	tf, err := os.Create(targetsFile)
	if err != nil {
		return fmt.Errorf("failed to create targets file: %w", err)
	}
	for _, u := range urls {
		tf.WriteString(u + "\n")
	}
	tf.Close()
	defer os.Remove(targetsFile) // Cleanup

	args := []string{
		"-l", targetsFile,
		"-jsonl",
		"-o", outputFile,
	}

	// Add templates
	for _, t := range a.Config.VulnerabilityTemplates {
		args = append(args, "-t", t)
	}

	// Add tags
	if len(a.Config.VulnerabilityTags) > 0 {
		args = append(args, "-tags", strings.Join(a.Config.VulnerabilityTags, ","))
	}

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Check if output file was created (vulnerability scanner may exit with non-zero but still produce results)
		if info, statErr := os.Stat(outputFile); statErr == nil && info.Size() > 0 {
			log.Printf("%s: ScanVulnerabilities: Exited with error but produced output", domain)
			if count, err := countVulnerabilityFindings(outputFile); err == nil {
				log.Printf("%s: ScanVulnerabilities: Completed - found %d vulnerabilities", domain, count)
			}
			return nil
		}
		return fmt.Errorf("vulnerability scan failed: %v, stderr: %s", err, stderr.String())
	}

	// vulnerability scan completed successfully
	if count, err := countVulnerabilityFindings(outputFile); err == nil {
		log.Printf("%s: ScanVulnerabilities: Completed - found %d vulnerabilities", domain, count)
	} else {
		log.Printf("%s: ScanVulnerabilities: Completed - no vulnerabilities found", domain)
	}

	return nil
}

func (a *Activities) GenerateReport(ctx context.Context, domain string) error {
	log.Printf("%s: GenerateReport: Starting...", domain)
	outDir := filepath.Join(a.Config.OutputDir, domain)

	// Helper to count lines/records in JSONL
	countLines := func(filename string) (int, error) {
		f, err := os.Open(filename)
		if err != nil {
			if os.IsNotExist(err) {
				return 0, nil
			}
			return 0, err
		}
		defer f.Close()
		count := 0
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			count++
		}
		return count, scanner.Err()
	}

	subdomainsCount, _ := countLines(filepath.Join(outDir, "subdomains.jsonl"))
	liveHostsCount, _ := countLines(filepath.Join(outDir, "live_hosts.jsonl"))

	// Parse findings for detailed report
	var findings []VulnerabilityFinding
	findingsFile, err := os.Open(filepath.Join(outDir, "vulnerability_findings.jsonl"))
	if err == nil {
		defer findingsFile.Close()
		scanner := bufio.NewScanner(findingsFile)
		for scanner.Scan() {
			var f VulnerabilityFinding
			if err := json.Unmarshal(scanner.Bytes(), &f); err == nil {
				findings = append(findings, f)
			}
		}
	}

	// Template data
	data := struct {
		Domain          string
		Timestamp       string
		SubdomainsCount int
		LiveHostsCount  int
		Findings        []VulnerabilityFinding
		FindingsCount   int
	}{
		Domain:          domain,
		Timestamp:       time.Now().Format(time.RFC3339),
		SubdomainsCount: subdomainsCount,
		LiveHostsCount:  liveHostsCount,
		Findings:        findings,
		FindingsCount:   len(findings),
	}

	// Helper function to format CVE IDs
	formatCVE := func(cveID interface{}) string {
		if cveID == nil {
			return "-"
		}
		switch v := cveID.(type) {
		case string:
			if v == "" {
				return "-"
			}
			return v
		case []interface{}:
			if len(v) == 0 {
				return "-"
			}
			var cves []string
			for _, cve := range v {
				if cveStr, ok := cve.(string); ok && cveStr != "" {
					cves = append(cves, cveStr)
				}
			}
			if len(cves) == 0 {
				return "-"
			}
			return strings.Join(cves, ", ")
		default:
			return "-"
		}
	}

	tmpl := `# Reconnaissance Report for {{.Domain}}
Generated at: {{.Timestamp}}

## Summary
- **Subdomains Found**: {{.SubdomainsCount}}
- **Live HOSTS**: {{.LiveHostsCount}}
- **Vulnerabilities**: {{.FindingsCount}}

## Vulnerability Findings
{{if .Findings}}
| Severity | Name | CVE | Matched At |
|----------|------|-----|------------|
{{range .Findings}}| {{.Info.Severity}} | {{.Info.Name}} | {{if .Info.Classification}}{{formatCVE .Info.Classification.CVEID}}{{else}}-{{end}} | {{.MatchedAt}} |
{{end}}
{{else}}
No vulnerabilities found.
{{end}}
`

	t, err := template.New("report").Funcs(template.FuncMap{
		"formatCVE": formatCVE,
	}).Parse(tmpl)
	if err != nil {
		return fmt.Errorf("failed to parse report template: %w", err)
	}

	reportFile := filepath.Join(outDir, "report.md")
	f, err := os.Create(reportFile)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	if err := t.Execute(f, data); err != nil {
		return fmt.Errorf("failed to execute report template: %w", err)
	}

	// Also update global summary (simple append for now)
	summaryFile := filepath.Join(a.Config.OutputDir, "report-summary.md")
	sf, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open summary file: %w", err)
	}
	defer sf.Close()

	summaryLine := fmt.Sprintf("- **%s**: %d subdomains, %d live, %d findings\n", domain, subdomainsCount, liveHostsCount, len(findings))
	if _, err := sf.WriteString(summaryLine); err != nil {
		return fmt.Errorf("failed to write to summary file: %w", err)
	}

	log.Printf("%s: GenerateReport: Completed - %d subdomains, %d live hosts, %d findings", domain, subdomainsCount, liveHostsCount, len(findings))
	return nil
}
