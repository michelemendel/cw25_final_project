package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cschleiden/go-workflows/backend/sqlite"
	"github.com/cschleiden/go-workflows/client"
	"github.com/cschleiden/go-workflows/worker"
	"github.com/cschleiden/go-workflows/workflow"
	"gopkg.in/yaml.v3"
)

// ToolStatus represents the availability and type of a tool
type ToolStatus struct {
	Available bool
	IsMock    bool
	Path      string
}

// checkTool checks if a tool is available and whether it's a mock or real tool
func checkTool(toolName string) ToolStatus {
	path, err := exec.LookPath(toolName)
	log.Printf("----- Checking tool: %s, path: %s", toolName, path)
	if err != nil {
		return ToolStatus{Available: false, IsMock: false, Path: ""}
	}

	// Check if the path contains "mock_tools" to determine if it's a mock
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	isMock := strings.Contains(absPath, "mock_tools")

	return ToolStatus{
		Available: true,
		IsMock:    isMock,
		Path:      absPath,
	}
}

// validateTools checks all required tools and prints their status
func validateTools(cfg *Config) {
	tools := []string{"subfinder", "httpx", "nuclei"}
	log.Println("=== Tool Validation ===")

	allReal := true
	anyMissing := false

	// Check required tools
	for _, tool := range tools {
		status := checkTool(tool)
		if !status.Available {
			log.Printf("❌ %s: NOT FOUND", tool)
			anyMissing = true
		} else if status.IsMock {
			log.Printf("⚠️ %s: MOCK TOOL (path: %s)", tool, status.Path)
			allReal = false
		} else {
			log.Printf("✅ %s: REAL TOOL (path: %s)", tool, status.Path)
		}
	}

	// Check brute-force tools if enabled
	if cfg != nil && cfg.Subfinder.BruteForce {
		log.Println("--- Brute-force tools (required when brute_force is enabled) ---")
		bruteForceTools := []string{"puredns", "massdns"}
		for _, tool := range bruteForceTools {
			status := checkTool(tool)
			if !status.Available {
				log.Printf("❌ %s: NOT FOUND", tool)
				anyMissing = true
			} else if status.IsMock {
				log.Printf("⚠️ %s: MOCK TOOL (path: %s)", tool, status.Path)
				allReal = false
			} else {
				log.Printf("✅ %s: REAL TOOL (path: %s)", tool, status.Path)
			}
		}
	}

	log.Println("=======================")

	if anyMissing {
		if cfg != nil && cfg.Subfinder.BruteForce {
			log.Fatal("ERROR: Some required tools are missing. Please install them or disable brute_force in config.yaml.")
		} else {
			log.Fatal("ERROR: Some required tools are missing. Please install them or use 'make run-mock' to use mock tools.")
		}
	}

	if !allReal {
		log.Println("WARNING: Some tools are mock tools. Results will contain fake data.")
		log.Println("To use real tools, ensure they are installed and in your PATH.")
	} else {
		log.Println("All tools validated - using REAL tools for reconnaissance.")
	}
	log.Println()
}

// loadConfig loads and parses the configuration file, and prepares the output directory
func loadConfig(configFile string) (*Config, error) {
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		return nil, err
	}

	// Clean output directory before starting (remove old results)
	log.Printf("Cleaning output directory: %s", cfg.OutputDir)
	if err := os.RemoveAll(cfg.OutputDir); err != nil {
		log.Printf("Warning: Failed to clean output directory: %v", err)
	}

	// Force create output directory
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, err
	}
	log.Println("Output directory cleaned and ready for new results.")

	return &cfg, nil
}

// parseDomains reads and parses the domains file, skipping empty lines and comments
func parseDomains(domainsFile string) ([]string, error) {
	file, err := os.Open(domainsFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		d := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments (lines starting with #)
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		domains = append(domains, d)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

// startWorkflows initializes the workflow backend, starts the worker, and executes workflows for all domains
func startWorkflows(cfg *Config, domains []string) {
	// Initialize Workflow Backend
	b := sqlite.NewInMemoryBackend()

	// Start Worker
	c := client.New(b)
	w := worker.New(b, nil)

	activities := &Activities{Config: cfg}

	w.RegisterWorkflow(ReconWorkflow)
	w.RegisterActivity(activities)

	if err := w.Start(context.Background()); err != nil {
		log.Fatalf("Failed to start worker: %v", err)
	}

	// Start Workflows
	ctx := context.Background()
	// Use workflow.Instance type
	var runs []*workflow.Instance

	// Track workflow timing
	type workflowTiming struct {
		domain    string
		startTime time.Time
		endTime   time.Time
		completed bool
		err       error
	}
	workflowTimings := make(map[string]*workflowTiming)
	var timingsMutex sync.RWMutex
	overallStartTime := time.Now()

	for _, domain := range domains {
		log.Printf("%s: Starting workflow", domain)
		run, err := c.CreateWorkflowInstance(ctx, client.WorkflowInstanceOptions{
			InstanceID: "recon-" + domain,
		}, ReconWorkflow, domain)
		if err != nil {
			log.Printf("%s: Failed to create workflow: %v", domain, err)
			continue
		}
		runs = append(runs, run)
		workflowTimings[run.InstanceID] = &workflowTiming{
			domain:    domain,
			startTime: time.Now(),
			completed: false,
		}
	}

	// Wait for completion with progress indicator
	// Parse timeout from config, default to 60 minutes for large scans
	workflowTimeout := 60 * time.Minute
	if cfg.Timeout != "" {
		if parsedTimeout, err := time.ParseDuration(cfg.Timeout); err == nil {
			// Use config timeout, but ensure minimum of 30 minutes for large scans
			if parsedTimeout < 30*time.Minute {
				log.Printf("Warning: Config timeout (%v) is less than 30 minutes. Using 30 minutes minimum for large scans.", parsedTimeout)
				workflowTimeout = 30 * time.Minute
			} else {
				workflowTimeout = parsedTimeout
			}
		} else {
			log.Printf("Warning: Failed to parse timeout from config (%s), using default 60 minutes", cfg.Timeout)
		}
	}
	log.Printf("Workflow timeout set to: %v", workflowTimeout)

	// Start progress indicator goroutine
	progressCtx, progressCancel := context.WithCancel(ctx)
	progressDone := make(chan bool)
	go func() {
		ticker := time.NewTicker(10 * time.Second) // Update every 10 seconds
		defer ticker.Stop()
		for {
			select {
			case <-progressCtx.Done():
				progressDone <- true
				return
			case <-ticker.C:
				// Count running workflows
				running := 0
				completed := 0
				timingsMutex.RLock()
				for _, timing := range workflowTimings {
					if timing.completed {
						completed++
					} else {
						running++
					}
				}
				total := len(workflowTimings)
				timingsMutex.RUnlock()
				elapsed := time.Since(overallStartTime)
				log.Printf("⏳ Progress: %d running, %d of %d completed | Elapsed: %v", running, completed, total, elapsed.Round(time.Second))
			}
		}
	}()

	// Wait for all workflows concurrently
	var wg sync.WaitGroup
	for _, run := range runs {
		wg.Add(1)
		go func(run *workflow.Instance) {
			defer wg.Done()
			timingsMutex.RLock()
			timing := workflowTimings[run.InstanceID]
			startTime := timing.startTime
			domain := timing.domain
			timingsMutex.RUnlock()

			if err := c.WaitForWorkflowInstance(ctx, run, workflowTimeout); err != nil {
				endTime := time.Now()
				timingsMutex.Lock()
				timing.endTime = endTime
				timing.completed = true
				timing.err = err
				timingsMutex.Unlock()
				log.Printf("❌ %s: Workflow recon failed or timed out: %v", domain, err)
			} else {
				endTime := time.Now()
				timingsMutex.Lock()
				timing.endTime = endTime
				timing.completed = true
				timingsMutex.Unlock()
				duration := endTime.Sub(startTime)
				log.Printf("✅ %s: Workflow recon completed in %v", domain, duration.Round(time.Second))
			}
		}(run)
	}
	wg.Wait()

	// Stop progress indicator
	progressCancel()
	<-progressDone

	// Print timing summary
	overallEndTime := time.Now()
	overallDuration := overallEndTime.Sub(overallStartTime)
	log.Println()
	log.Println("=" + strings.Repeat("=", 60) + "=")
	log.Println("TIMING SUMMARY")
	log.Println("=" + strings.Repeat("=", 60) + "=")
	for _, run := range runs {
		timing := workflowTimings[run.InstanceID]
		if timing.completed {
			duration := timing.endTime.Sub(timing.startTime)
			status := "✅"
			if timing.err != nil {
				status = "❌"
			}
			log.Printf("%s %s: %v", status, timing.domain, duration.Round(time.Second))
		}
	}
	log.Println(strings.Repeat("-", 62))
	log.Printf("Total time: %v", overallDuration.Round(time.Second))
	log.Println("=" + strings.Repeat("=", 60) + "=")
	log.Println()

	// Write timing summary to report-summary.md
	summaryFile := filepath.Join(cfg.OutputDir, "report-summary.md")
	sf, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer sf.Close()
		sf.WriteString("\n## Timing Summary\n\n")
		sf.WriteString("```\n")
		sf.WriteString(strings.Repeat("=", 62) + "\n")
		sf.WriteString("TIMING SUMMARY\n")
		sf.WriteString(strings.Repeat("=", 62) + "\n")
		for _, run := range runs {
			timing := workflowTimings[run.InstanceID]
			if timing.completed {
				duration := timing.endTime.Sub(timing.startTime)
				status := "✅"
				if timing.err != nil {
					status = "❌"
				}
				sf.WriteString(fmt.Sprintf("%s %s: %v\n", status, timing.domain, duration.Round(time.Second)))
			}
		}
		sf.WriteString(strings.Repeat("-", 62) + "\n")
		sf.WriteString(fmt.Sprintf("Total time: %v\n", overallDuration.Round(time.Second)))
		sf.WriteString(strings.Repeat("=", 62) + "\n")
		sf.WriteString("```\n")
	} else {
		log.Printf("Warning: Failed to write timing summary to file: %v", err)
	}

	log.Println("All tasks completed.")
}

func main() {
	configFile := flag.String("config", "config.yaml", "Path to configuration file")
	domainsFile := flag.String("domains", "domains.txt", "Path to domains file")
	flag.Parse()

	// Load config first to check if brute-force is enabled
	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Validate tools (including brute-force tools if enabled)
	validateTools(cfg)

	domains, err := parseDomains(*domainsFile)
	if err != nil {
		log.Fatalf("Failed to parse domains: %v", err)
	}

	startWorkflows(cfg, domains)
}
