# Phase 2: Admin Panel & Configuration Management

## Learning Objectives

By the end of Phase 2, you'll understand:
- Web-based administration interfaces
- Real-time data visualization with WebSockets
- Dynamic configuration management (hot-reload)
- YAML-based rule systems
- Authentication and session management
- RESTful API design for admin operations
- Template-based web rendering

## Core Concepts Overview

### 1. Admin Architecture Pattern

The admin panel follows a **separation of concerns** approach:

```
Admin Panel Architecture:
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Frontend  │◄──►│   Admin Server   │◄──►│   WAF Engine    │
│  (HTML/JS/CSS)  │    │  (HTTP Handlers) │    │  (Core Logic)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         ▲                        ▲                       ▲
         │                        │                       │
    Templates &              REST APIs &              Live Metrics &
    Static Assets           WebSocket               Configuration
```

### 2. Configuration Management Concepts

- **Hot Reload**: Update rules without restarting the service
- **YAML Configuration**: Human-readable rule definitions  
- **Configuration Validation**: Ensure rules are syntactically correct
- **Version Control**: Track configuration changes

## Step-by-Step Implementation

### Step 1: Configuration System Foundation

First, let's build a flexible configuration system:

```go
// internal/config/types.go
package config

import (
    "time"
)

// WAFConfig represents the complete WAF configuration
type WAFConfig struct {
    Server     ServerConfig     `yaml:"server"`
    Engine     EngineConfig     `yaml:"engine"`
    RateLimit  RateLimitConfig  `yaml:"rate_limit"`
    Rules      RulesConfig      `yaml:"rules"`
    Database   DatabaseConfig   `yaml:"database"`
    Admin      AdminConfig      `yaml:"admin"`
}

type ServerConfig struct {
    Host         string        `yaml:"host"`
    Port         int           `yaml:"port"`
    ReadTimeout  time.Duration `yaml:"read_timeout"`
    WriteTimeout time.Duration `yaml:"write_timeout"`
}

type EngineConfig struct {
    MaxBodySize     int64         `yaml:"max_body_size"`
    RequestTimeout  time.Duration `yaml:"request_timeout"`
    EnableLogging   bool          `yaml:"enable_logging"`
    LogLevel        string        `yaml:"log_level"`
}

type RateLimitConfig struct {
    Enabled            bool          `yaml:"enabled"`
    RequestsPerMinute  int           `yaml:"requests_per_minute"`
    BurstSize          int           `yaml:"burst_size"`
    CleanupInterval    time.Duration `yaml:"cleanup_interval"`
}

type RulesConfig struct {
    ConfigPath      string        `yaml:"config_path"`
    AutoReload      bool          `yaml:"auto_reload"`
    ReloadInterval  time.Duration `yaml:"reload_interval"`
}

type AdminConfig struct {
    Enabled    bool   `yaml:"enabled"`
    Host       string `yaml:"host"`
    Port       int    `yaml:"port"`
    Username   string `yaml:"username"`
    Password   string `yaml:"password"` // In production, use proper auth
    JWTSecret  string `yaml:"jwt_secret"`
}

// Rule represents a single WAF rule
type Rule struct {
    ID          string            `yaml:"id" json:"id"`
    Name        string            `yaml:"name" json:"name"`
    Description string            `yaml:"description" json:"description"`
    Category    string            `yaml:"category" json:"category"`
    Enabled     bool              `yaml:"enabled" json:"enabled"`
    Priority    int               `yaml:"priority" json:"priority"`
    Action      string            `yaml:"action" json:"action"` // allow, block, log
    Conditions  []RuleCondition   `yaml:"conditions" json:"conditions"`
    Metadata    map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

type RuleCondition struct {
    Field    string `yaml:"field" json:"field"`       // url, body, header, etc.
    Operator string `yaml:"operator" json:"operator"` // contains, regex, equals
    Value    string `yaml:"value" json:"value"`
    Negate   bool   `yaml:"negate,omitempty" json:"negate,omitempty"`
}
```

**Learning Point**: YAML configuration provides human-readable rules while Go structs provide type safety and validation.

### Step 2: Configuration Loader with Hot Reload

```go
// internal/config/loader.go
package config

import (
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"
    
    "gopkg.in/yaml.v3"
    "gopkg.in/fsnotify.v1"
)

// ConfigManager handles loading and reloading configuration
type ConfigManager struct {
    config    *WAFConfig
    rules     []Rule
    configPath string
    rulesPath  string
    
    mu         sync.RWMutex
    watcher    *fsnotify.Watcher
    
    // Callbacks for configuration changes
    onConfigChange func(*WAFConfig)
    onRulesChange  func([]Rule)
}

func NewConfigManager(configPath string) (*ConfigManager, error) {
    cm := &ConfigManager{
        configPath: configPath,
    }
    
    // Load initial configuration
    if err := cm.LoadConfig(); err != nil {
        return nil, fmt.Errorf("failed to load config: %w", err)
    }
    
    // Set up file watcher for hot reload
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return nil, fmt.Errorf("failed to create watcher: %w", err)
    }
    cm.watcher = watcher
    
    return cm, nil
}

func (cm *ConfigManager) LoadConfig() error {
    data, err := os.ReadFile(cm.configPath)
    if err != nil {
        return fmt.Errorf("failed to read config file: %w", err)
    }
    
    var config WAFConfig
    if err := yaml.Unmarshal(data, &config); err != nil {
        return fmt.Errorf("failed to parse config: %w", err)
    }
    
    // Validate configuration
    if err := cm.validateConfig(&config); err != nil {
        return fmt.Errorf("invalid configuration: %w", err)
    }
    
    cm.mu.Lock()
    cm.config = &config
    cm.rulesPath = config.Rules.ConfigPath
    cm.mu.Unlock()
    
    // Load rules if path is specified
    if config.Rules.ConfigPath != "" {
        if err := cm.LoadRules(); err != nil {
            return fmt.Errorf("failed to load rules: %w", err)
        }
    }
    
    return nil
}

func (cm *ConfigManager) LoadRules() error {
    if cm.rulesPath == "" {
        return nil
    }
    
    var allRules []Rule
    
    // Walk through rules directory
    err := filepath.Walk(cm.rulesPath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        
        if filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml" {
            rules, err := cm.loadRuleFile(path)
            if err != nil {
                return fmt.Errorf("failed to load rule file %s: %w", path, err)
            }
            allRules = append(allRules, rules...)
        }
        
        return nil
    })
    
    if err != nil {
        return err
    }
    
    cm.mu.Lock()
    cm.rules = allRules
    cm.mu.Unlock()
    
    return nil
}

func (cm *ConfigManager) loadRuleFile(path string) ([]Rule, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    
    var ruleFile struct {
        Rules []Rule `yaml:"rules"`
    }
    
    if err := yaml.Unmarshal(data, &ruleFile); err != nil {
        return nil, err
    }
    
    // Validate each rule
    for _, rule := range ruleFile.Rules {
        if err := cm.validateRule(&rule); err != nil {
            return nil, fmt.Errorf("invalid rule %s: %w", rule.ID, err)
        }
    }
    
    return ruleFile.Rules, nil
}

func (cm *ConfigManager) validateConfig(config *WAFConfig) error {
    if config.Server.Port <= 0 || config.Server.Port > 65535 {
        return fmt.Errorf("invalid server port: %d", config.Server.Port)
    }
    
    if config.Engine.MaxBodySize <= 0 {
        return fmt.Errorf("max_body_size must be positive")
    }
    
    return nil
}

func (cm *ConfigManager) validateRule(rule *Rule) error {
    if rule.ID == "" {
        return fmt.Errorf("rule ID cannot be empty")
    }
    
    validActions := map[string]bool{
        "allow": true, "block": true, "log": true,
    }
    
    if !validActions[rule.Action] {
        return fmt.Errorf("invalid action: %s", rule.Action)
    }
    
    return nil
}

// StartWatching begins monitoring configuration files for changes
func (cm *ConfigManager) StartWatching() error {
    // Watch main config file
    if err := cm.watcher.Add(cm.configPath); err != nil {
        return err
    }
    
    // Watch rules directory
    if cm.rulesPath != "" {
        if err := cm.watcher.Add(cm.rulesPath); err != nil {
            return err
        }
    }
    
    go cm.watchLoop()
    return nil
}

func (cm *ConfigManager) watchLoop() {
    for {
        select {
        case event, ok := <-cm.watcher.Events:
            if !ok {
                return
            }
            
            if event.Op&fsnotify.Write == fsnotify.Write {
                // Debounce rapid file changes
                time.Sleep(100 * time.Millisecond)
                
                if event.Name == cm.configPath {
                    fmt.Println("Config file changed, reloading...")
                    if err := cm.LoadConfig(); err != nil {
                        fmt.Printf("Failed to reload config: %v\n", err)
                    } else if cm.onConfigChange != nil {
                        cm.onConfigChange(cm.GetConfig())
                    }
                } else if filepath.Dir(event.Name) == cm.rulesPath {
                    fmt.Println("Rules changed, reloading...")
                    if err := cm.LoadRules(); err != nil {
                        fmt.Printf("Failed to reload rules: %v\n", err)
                    } else if cm.onRulesChange != nil {
                        cm.onRulesChange(cm.GetRules())
                    }
                }
            }
            
        case err, ok := <-cm.watcher.Errors:
            if !ok {
                return
            }
            fmt.Printf("Watcher error: %v\n", err)
        }
    }
}

// Getters with read locks
func (cm *ConfigManager) GetConfig() *WAFConfig {
    cm.mu.RLock()
    defer cm.mu.RUnlock()
    
    // Return a copy to prevent external modification
    configCopy := *cm.config
    return &configCopy
}

func (cm *ConfigManager) GetRules() []Rule {
    cm.mu.RLock()
    defer cm.mu.RUnlock()
    
    // Return a copy
    rulesCopy := make([]Rule, len(cm.rules))
    copy(rulesCopy, cm.rules)
    return rulesCopy
}

// Set callbacks for configuration changes
func (cm *ConfigManager) OnConfigChange(callback func(*WAFConfig)) {
    cm.onConfigChange = callback
}

func (cm *ConfigManager) OnRulesChange(callback func([]Rule)) {
    cm.onRulesChange = callback
}
```

**Learning Points**:
- **File Watching**: Automatically reload when files change
- **Thread Safety**: Multiple goroutines access configuration
- **Validation**: Prevent invalid configurations from breaking the system
- **Debouncing**: Handle rapid file system events gracefully

### Step 3: Admin HTTP Server Foundation

```go
// internal/admin/server.go
package admin

import (
    "context"
    "encoding/json"
    "fmt"
    "html/template"
    "net/http"
    "path/filepath"
    "time"
    
    "your-project/internal/config"
    "your-project/pkg/models"
)

// AdminServer provides the web interface for WAF management
type AdminServer struct {
    config        *config.AdminConfig
    configManager *config.ConfigManager
    wafEngine     WAFEngineInterface // Interface to avoid circular dependency
    
    server      *http.Server
    templates   *template.Template
    
    // Real-time metrics
    metricsHub  *MetricsHub
}

// WAFEngineInterface allows admin to interact with WAF without circular imports
type WAFEngineInterface interface {
    GetMetrics() *models.Metrics
    AddFilter(filter models.Filter)
    RemoveFilter(filterName string)
    GetActiveFilters() []string
}

func NewAdminServer(config *config.AdminConfig, configManager *config.ConfigManager, wafEngine WAFEngineInterface) *AdminServer {
    return &AdminServer{
        config:        config,
        configManager: configManager,
        wafEngine:     wafEngine,
        metricsHub:    NewMetricsHub(),
    }
}

func (s *AdminServer) Start() error {
    // Load HTML templates
    if err := s.loadTemplates(); err != nil {
        return fmt.Errorf("failed to load templates: %w", err)
    }
    
    // Set up routes
    mux := http.NewServeMux()
    s.setupRoutes(mux)
    
    // Create HTTP server
    s.server = &http.Server{
        Addr:         fmt.Sprintf("%s:%d", s.config.Host, s.config.Port),
        Handler:      s.corsMiddleware(s.authMiddleware(mux)),
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
    }
    
    fmt.Printf("Admin panel starting on %s\n", s.server.Addr)
    return s.server.ListenAndServe()
}

func (s *AdminServer) setupRoutes(mux *http.ServeMux) {
    // Static files
    mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
    
    // HTML pages
    mux.HandleFunc("/", s.handleDashboard)
    mux.HandleFunc("/login", s.handleLogin)
    mux.HandleFunc("/rules", s.handleRules)
    mux.HandleFunc("/events", s.handleEvents)
    mux.HandleFunc("/config", s.handleConfig)
    
    // API endpoints
    mux.HandleFunc("/api/login", s.handleAPILogin)
    mux.HandleFunc("/api/metrics", s.handleAPIMetrics)
    mux.HandleFunc("/api/rules", s.handleAPIRules)
    mux.HandleFunc("/api/events", s.handleAPIEvents)
    mux.HandleFunc("/api/config", s.handleAPIConfig)
    
    // WebSocket for real-time updates
    mux.HandleFunc("/ws/metrics", s.handleWebSocketMetrics)
}

func (s *AdminServer) loadTemplates() error {
    templates := template.New("admin")
    
    // Load all template files
    err := filepath.Walk("web/templates", func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        
        if filepath.Ext(path) == ".html" {
            _, err := templates.ParseFiles(path)
            return err
        }
        
        return nil
    })
    
    if err != nil {
        return err
    }
    
    s.templates = templates
    return nil
}
```

### Step 4: Authentication Middleware

```go
// internal/admin/auth.go
package admin

import (
    "encoding/json"
    "net/http"
    "strings"
    "time"
    
    "github.com/golang-jwt/jwt/v4"
)

type Claims struct {
    Username string `json:"username"`
    Role     string `json:"role"`
    jwt.RegisteredClaims
}

func (s *AdminServer) authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Skip auth for login page and API login
        if r.URL.Path == "/login" || r.URL.Path == "/api/login" {
            next.ServeHTTP(w, r)
            return
        }
        
        // Check for JWT token
        tokenString := s.extractToken(r)
        if tokenString == "" {
            s.redirectToLogin(w, r)
            return
        }
        
        // Validate token
        claims, err := s.validateToken(tokenString)
        if err != nil {
            s.redirectToLogin(w, r)
            return
        }
        
        // Add user info to request context
        ctx := r.Context()
        ctx = context.WithValue(ctx, "user", claims.Username)
        ctx = context.WithValue(ctx, "role", claims.Role)
        r = r.WithContext(ctx)
        
        next.ServeHTTP(w, r)
    })
}

func (s *AdminServer) extractToken(r *http.Request) string {
    // Check Authorization header
    authHeader := r.Header.Get("Authorization")
    if strings.HasPrefix(authHeader, "Bearer ") {
        return strings.TrimPrefix(authHeader, "Bearer ")
    }
    
    // Check cookie
    cookie, err := r.Cookie("auth_token")
    if err == nil {
        return cookie.Value
    }
    
    return ""
}

func (s *AdminServer) validateToken(tokenString string) (*Claims, error) {
    claims := &Claims{}
    
    token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
        return []byte(s.config.JWTSecret), nil
    })
    
    if err != nil || !token.Valid {
        return nil, err
    }
    
    return claims, nil
}

func (s *AdminServer) generateToken(username, role string) (string, error) {
    claims := &Claims{
        Username: username,
        Role:     role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(s.config.JWTSecret))
}

func (s *AdminServer) handleAPILogin(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    var loginReq struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    
    // Simple authentication (in production, use proper password hashing)
    if loginReq.Username != s.config.Username || loginReq.Password != s.config.Password {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }
    
    // Generate JWT token
    token, err := s.generateToken(loginReq.Username, "admin")
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }
    
    // Set cookie and return token
    http.SetCookie(w, &http.Cookie{
        Name:     "auth_token",
        Value:    token,
        Expires:  time.Now().Add(24 * time.Hour),
        HttpOnly: true,
        Secure:   false, // Set to true in production with HTTPS
    })
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "token": token,
        "status": "success",
    })
}

func (s *AdminServer) redirectToLogin(w http.ResponseWriter, r *http.Request) {
    if strings.HasPrefix(r.URL.Path, "/api/") {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
    } else {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    }
}
```

**Learning Points**:
- **JWT Tokens**: Stateless authentication for web APIs
- **Middleware Pattern**: Clean separation of concerns
- **Cookie vs Header Auth**: Support both web browser and API clients
- **Context Values**: Pass user information through request pipeline

### Step 5: Dashboard with Real-time Metrics

```go
// internal/admin/metrics.go
package admin

import (
    "encoding/json"
    "log"
    "net/http"
    "sync"
    "time"
    
    "github.com/gorilla/websocket"
    "your-project/pkg/models"
)

// MetricsHub manages real-time metric distribution
type MetricsHub struct {
    clients    map[*websocket.Conn]bool
    broadcast  chan []byte
    register   chan *websocket.Conn
    unregister chan *websocket.Conn
    mu         sync.RWMutex
}

func NewMetricsHub() *MetricsHub {
    return &MetricsHub{
        clients:    make(map[*websocket.Conn]bool),
        broadcast:  make(chan []byte),
        register:   make(chan *websocket.Conn),
        unregister: make(chan *websocket.Conn),
    }
}

func (h *MetricsHub) Start() {
    go h.run()
    go h.metricsLoop()
}

func (h *MetricsHub) run() {
    for {
        select {
        case client := <-h.register:
            h.mu.Lock()
            h.clients[client] = true
            h.mu.Unlock()
            log.Println("New WebSocket client connected")
            
        case client := <-h.unregister:
            h.mu.Lock()
            if _, ok := h.clients[client]; ok {
                delete(h.clients, client)
                client.Close()
            }
            h.mu.Unlock()
            log.Println("WebSocket client disconnected")
            
        case message := <-h.broadcast:
            h.mu.RLock()
            for client := range h.clients {
                select {
                case client.WriteMessage(websocket.TextMessage, message):
                default:
                    close(client)
                    delete(h.clients, client)
                }
            }
            h.mu.RUnlock()
        }
    }
}

func (h *MetricsHub) metricsLoop() {
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        // This would get actual metrics from your WAF engine
        metrics := h.getCurrentMetrics()
        
        data, err := json.Marshal(metrics)
        if err != nil {
            continue
        }
        
        select {
        case h.broadcast <- data:
        default:
            // Channel is full, skip this update
        }
    }
}

func (h *MetricsHub) getCurrentMetrics() map[string]interface{} {
    // In a real implementation, this would get metrics from your WAF engine
    return map[string]interface{}{
        "timestamp":      time.Now().Unix(),
        "requests_per_second": 45,
        "blocked_requests":    12,
        "active_connections":  150,
        "cpu_usage":          35.5,
        "memory_usage":       67.8,
        "top_blocked_ips": []string{"192.168.1.100", "10.0.0.50"},
        "attack_types": map[string]int{
            "sql_injection": 8,
            "xss":          4,
            "rate_limit":   15,
        },
    }
}

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        // In production, implement proper origin checking
        return true
    },
}

func (s *AdminServer) handleWebSocketMetrics(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println("WebSocket upgrade failed:", err)
        return
    }
    
    // Register client
    s.metricsHub.register <- conn
    
    // Handle client disconnection
    defer func() {
        s.metricsHub.unregister <- conn
    }()
    
    // Keep connection alive
    for {
        _, _, err := conn.ReadMessage()
        if err != nil {
            break
        }
    }
}

func (s *AdminServer) handleAPIMetrics(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    metrics := s.metricsHub.getCurrentMetrics()
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(metrics)
}
```

### Step 6: HTML Templates for Admin Interface

```go
// internal/admin/handlers.go
package admin

import (
    "net/http"
)

func (s *AdminServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
    data := struct {
        Title string
        User  string
    }{
        Title: "WAF Dashboard",
        User:  r.Context().Value("user").(string),
    }
    
    if err := s.templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
        http.Error(w, "Template error", http.StatusInternalServerError)
        return
    }
}

func (s *AdminServer) handleRules(w http.ResponseWriter, r *http.Request) {
    rules := s.configManager.GetRules()
    
    data := struct {
        Title string
        Rules []config.Rule
    }{
        Title: "WAF Rules",
        Rules: rules,
    }
    
    if err := s.templates.ExecuteTemplate(w, "rules.html", data); err != nil {
        http.Error(w, "Template error", http.StatusInternalServerError)
        return
    }
}

func (s *AdminServer) handleLogin(w http.ResponseWriter, r *http.Request) {
    if err := s.templates.ExecuteTemplate(w, "login.html", nil); err != nil {
        http.Error(w, "Template error", http.StatusInternalServerError)
        return
    }
}
```

### Step 7: Sample YAML Rule Files

```yaml
# configs/rules/sql-injection.yaml
rules:
  - id: "sql-001"
    name: "Basic SQL Injection Detection"
    description: "Detects common SQL injection patterns"
    category: "sql_injection"
    enabled: true
    priority: 100
    action: "block"
    conditions:
      - field: "url"
        operator: "regex"
        value: "(?i)(union|select|insert|update|delete)\\s"
      - field: "body"
        operator: "contains"
        value: "' OR '1'='1"
    metadata:
      severity: "high"
      reference: "OWASP-A03"

  - id: "sql-002"
    name: "SQL Comment Injection"
    description: "Detects SQL comment-based attacks"
    category: "sql_injection"
    enabled: true
    priority: 110
    action: "block"
    conditions:
      - field: "url"
        operator: "regex"
        value: "(--|#|/\\*|\\*/)"
      - field: "body"
        operator: "regex"
        value: "(--|#|/\\*|\\*/)"
```

```yaml
# configs/rules/xss.yaml
rules:
  - id: "xss-001"
    name: "Script Tag Detection"
    description: "Detects script tag injections"
    category: "xss"
    enabled: true
    priority: 200
    action: "block"
    conditions:
      - field: "body"
        operator: "regex"
        value: "(?i)<script[^>]*>"
      - field: "url"
        operator: "contains"
        value: "<script>"
```

### Step 8: Frontend JavaScript for Real-time Updates

```javascript
// web/static/js/dashboard.js
class WAFDashboard {
    constructor() {
        this.ws = null;
        this.charts = {};
        this.init();
    }
    
    init() {
        this.connectWebSocket();
        this.initCharts();
        this.setupEventHandlers();
    }
    
    connectWebSocket() {
        const wsUrl = `ws://${window.location.host}/ws/metrics`;
        this.ws = new WebSocket(wsUrl);
        
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.showConnectionStatus('connected');
        };
        
        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.updateDashboard(data);
        };
        
        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.showConnectionStatus('disconnected');
            // Reconnect after 5 seconds
            setTimeout(() => this.connectWebSocket(), 5000);
        };
        
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }
    
    updateDashboard(data) {
        // Update metrics cards
        document.getElementById('requests-per-second').textContent = data.requests_per_second;
        document.getElementById('blocked-requests').textContent = data.blocked_requests;
        document.getElementById('active-connections').textContent = data.active_connections;
        
        // Update system metrics
        this.updateProgressBar('cpu-usage', data.cpu_usage);
        this.updateProgressBar('memory-usage', data.memory_usage);
        
        // Update charts
        this.updateRequestChart(data);
        this.updateAttackTypesChart(data.attack_types);
        
        // Update top blocked IPs
        this.updateBlockedIPsList(data.top_blocked_ips);
    }
    
    updateProgressBar(elementId, value) {
        const progressBar = document.getElementById(elementId);
        const progressFill = progressBar.querySelector('.progress-fill');
        const progressText = progressBar.querySelector('.progress-text');
        
        progressFill.style.width = `${value}%`;
        progressText.textContent = `${value.toFixed(1)}%`;
        
        // Color coding
        if (value > 80) {
            progressFill.className = 'progress-fill bg-danger';
        } else if (value > 60) {
            progressFill.className = 'progress-fill bg-warning';
        } else {
            progressFill.className = 'progress-fill bg-success';
        }
    }
    
    updateBlockedIPsList(ips) {
        const container = document.getElementById('blocked-ips-list');
        container.innerHTML = '';
        
        ips.forEach(ip => {
            const item = document.createElement('div');
            item.className = 'blocked-ip-item';
            item.innerHTML = `
                <span class="ip">${ip}</span>
                <button class="btn btn-sm btn-outline-primary" onclick="dashboard.showIPDetails('${ip}')">
                    Details
                </button>
            `;
            container.appendChild(item);
        });
    }
    
    showConnectionStatus(status) {
        const indicator = document.getElementById('connection-status');
        indicator.className = `connection-status ${status}`;
        indicator.textContent = status === 'connected' ? 'Connected' : 'Disconnected';
    }
    
    initCharts() {
        // Initialize Chart.js charts for real-time data visualization
        this.initRequestsChart();
        this.initAttackTypesChart();
    }
    
    initRequestsChart() {
        const ctx = document.getElementById('requests-chart').getContext('2d');
        this.charts.requests = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Requests/sec',
                    data: [],
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1,
                    fill: false
                }, {
                    label: 'Blocked/sec',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.1,
                    fill: false
                }]
            },
            options: {
                responsive: true,
                scales: {
                    x: { display: false },
                    y: { beginAtZero: true }
                },
                plugins: {
                    legend: { display: true }
                }
            }
        });
    }
    
    initAttackTypesChart() {
        const ctx = document.getElementById('attack-types-chart').getContext('2d');
        this.charts.attackTypes = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#FF6384', '#36A2EB', '#FFCE56', 
                        '#4BC0C0', '#9966FF', '#FF9F40'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    }
    
    updateRequestChart(data) {
        const chart = this.charts.requests;
        const now = new Date().toLocaleTimeString();
        
        // Add new data point
        chart.data.labels.push(now);
        chart.data.datasets[0].data.push(data.requests_per_second);
        chart.data.datasets[1].data.push(data.blocked_requests);
        
        // Keep only last 20 points
        if (chart.data.labels.length > 20) {
            chart.data.labels.shift();
            chart.data.datasets[0].data.shift();
            chart.data.datasets[1].data.shift();
        }
        
        chart.update('none'); // No animation for real-time updates
    }
    
    updateAttackTypesChart(attackTypes) {
        const chart = this.charts.attackTypes;
        
        chart.data.labels = Object.keys(attackTypes);
        chart.data.datasets[0].data = Object.values(attackTypes);
        
        chart.update();
    }
    
    setupEventHandlers() {
        // Rule management
        document.addEventListener('click', (e) => {
            if (e.target.matches('.toggle-rule')) {
                this.toggleRule(e.target.dataset.ruleId);
            }
            
            if (e.target.matches('.edit-rule')) {
                this.editRule(e.target.dataset.ruleId);
            }
            
            if (e.target.matches('.delete-rule')) {
                this.deleteRule(e.target.dataset.ruleId);
            }
        });
        
        // Configuration updates
        document.getElementById('save-config')?.addEventListener('click', () => {
            this.saveConfiguration();
        });
    }
    
    async toggleRule(ruleId) {
        try {
            const response = await fetch(`/api/rules/${ruleId}/toggle`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getAuthToken()}`
                }
            });
            
            if (response.ok) {
                this.showNotification('Rule updated successfully', 'success');
                this.refreshRulesList();
            } else {
                this.showNotification('Failed to update rule', 'error');
            }
        } catch (error) {
            console.error('Error toggling rule:', error);
            this.showNotification('Error updating rule', 'error');
        }
    }
    
    showNotification(message, type) {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }
    
    getAuthToken() {
        // Get token from cookie or localStorage
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'auth_token') {
                return value;
            }
        }
        return null;
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new WAFDashboard();
});
```

### Step 9: HTML Templates

```html
<!-- web/templates/dashboard.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <link href="/static/css/admin.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
</head>
<body>
    <div class="admin-container">
        <!-- Sidebar -->
        <nav class="sidebar">
            <div class="sidebar-header">
                <h3>WAF Admin</h3>
                <div id="connection-status" class="connection-status">Connecting...</div>
            </div>
            <ul class="sidebar-menu">
                <li><a href="/" class="active">Dashboard</a></li>
                <li><a href="/rules">Rules</a></li>
                <li><a href="/events">Security Events</a></li>
                <li><a href="/config">Configuration</a></li>
                <li><a href="/logs">Logs</a></li>
            </ul>
            <div class="sidebar-footer">
                <p>User: {{.User}}</p>
                <button onclick="logout()">Logout</button>
            </div>
        </nav>
        
        <!-- Main Content -->
        <main class="main-content">
            <div class="dashboard-header">
                <h1>Dashboard</h1>
                <div class="last-updated">
                    Last updated: <span id="last-updated">--</span>
                </div>
            </div>
            
            <!-- Metrics Cards -->
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-icon">🔄</div>
                    <div class="metric-value" id="requests-per-second">0</div>
                    <div class="metric-label">Requests/sec</div>
                </div>
                
                <div class="metric-card danger">
                    <div class="metric-icon">🛡️</div>
                    <div class="metric-value" id="blocked-requests">0</div>
                    <div class="metric-label">Blocked</div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-icon">👥</div>
                    <div class="metric-value" id="active-connections">0</div>
                    <div class="metric-label">Connections</div>
                </div>
            </div>
            
            <!-- Charts Section -->
            <div class="charts-grid">
                <div class="chart-container">
                    <h3>Traffic Overview</h3>
                    <canvas id="requests-chart"></canvas>
                </div>
                
                <div class="chart-container">
                    <h3>Attack Types</h3>
                    <canvas id="attack-types-chart"></canvas>
                </div>
            </div>
            
            <!-- System Health -->
            <div class="system-health">
                <h3>System Health</h3>
                <div class="health-metrics">
                    <div class="health-item">
                        <label>CPU Usage</label>
                        <div class="progress-bar" id="cpu-usage">
                            <div class="progress-fill"></div>
                            <div class="progress-text">0%</div>
                        </div>
                    </div>
                    
                    <div class="health-item">
                        <label>Memory Usage</label>
                        <div class="progress-bar" id="memory-usage">
                            <div class="progress-fill"></div>
                            <div class="progress-text">0%</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Recent Blocked IPs -->
            <div class="blocked-ips">
                <h3>Top Blocked IPs</h3>
                <div id="blocked-ips-list" class="blocked-ips-list">
                    <!-- Populated by JavaScript -->
                </div>
            </div>
        </main>
    </div>
    
    <script src="/static/js/dashboard.js"></script>
</body>
</html>
```

```html
<!-- web/templates/rules.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <link href="/static/css/admin.css" rel="stylesheet">
</head>
<body>
    <div class="admin-container">
        <nav class="sidebar">
            <!-- Same sidebar as dashboard -->
        </nav>
        
        <main class="main-content">
            <div class="page-header">
                <h1>WAF Rules</h1>
                <button class="btn btn-primary" onclick="showCreateRuleModal()">
                    Create Rule
                </button>
            </div>
            
            <div class="rules-container">
                <div class="rules-filters">
                    <select id="category-filter">
                        <option value="">All Categories</option>
                        <option value="sql_injection">SQL Injection</option>
                        <option value="xss">XSS</option>
                        <option value="rate_limit">Rate Limiting</option>
                    </select>
                    
                    <select id="status-filter">
                        <option value="">All Status</option>
                        <option value="enabled">Enabled</option>
                        <option value="disabled">Disabled</option>
                    </select>
                </div>
                
                <div class="rules-list">
                    {{range .Rules}}
                    <div class="rule-card {{if not .Enabled}}disabled{{end}}">
                        <div class="rule-header">
                            <div class="rule-info">
                                <h4>{{.Name}}</h4>
                                <span class="rule-category">{{.Category}}</span>
                                <span class="rule-priority">Priority: {{.Priority}}</span>
                            </div>
                            
                            <div class="rule-actions">
                                <label class="toggle-switch">
                                    <input type="checkbox" 
                                           {{if .Enabled}}checked{{end}}
                                           data-rule-id="{{.ID}}"
                                           class="toggle-rule">
                                    <span class="toggle-slider"></span>
                                </label>
                                
                                <button class="btn btn-sm btn-outline edit-rule" 
                                        data-rule-id="{{.ID}}">Edit</button>
                                <button class="btn btn-sm btn-outline-danger delete-rule" 
                                        data-rule-id="{{.ID}}">Delete</button>
                            </div>
                        </div>
                        
                        <div class="rule-description">
                            {{.Description}}
                        </div>
                        
                        <div class="rule-conditions">
                            <strong>Conditions:</strong>
                            {{range .Conditions}}
                            <div class="condition">
                                {{.Field}} {{.Operator}} "{{.Value}}"
                            </div>
                            {{end}}
                        </div>
                        
                        <div class="rule-action">
                            <strong>Action:</strong> 
                            <span class="action-badge action-{{.Action}}">{{.Action}}</span>
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
        </main>
    </div>
    
    <!-- Create/Edit Rule Modal -->
    <div id="rule-modal" class="modal">
        <div class="modal-content">
            <span class="modal-close">&times;</span>
            <h2 id="modal-title">Create Rule</h2>
            
            <form id="rule-form">
                <div class="form-group">
                    <label for="rule-name">Rule Name</label>
                    <input type="text" id="rule-name" name="name" required>
                </div>
                
                <div class="form-group">
                    <label for="rule-description">Description</label>
                    <textarea id="rule-description" name="description"></textarea>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="rule-category">Category</label>
                        <select id="rule-category" name="category">
                            <option value="sql_injection">SQL Injection</option>
                            <option value="xss">XSS</option>
                            <option value="csrf">CSRF</option>
                            <option value="rate_limit">Rate Limiting</option>
                            <option value="custom">Custom</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="rule-priority">Priority</label>
                        <input type="number" id="rule-priority" name="priority" min="1" max="1000" value="100">
                    </div>
                    
                    <div class="form-group">
                        <label for="rule-action">Action</label>
                        <select id="rule-action" name="action">
                            <option value="block">Block</option>
                            <option value="log">Log</option>
                            <option value="allow">Allow</option>
                        </select>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Conditions</label>
                    <div id="conditions-container">
                        <!-- Conditions will be added dynamically -->
                    </div>
                    <button type="button" onclick="addCondition()">Add Condition</button>
                </div>
                
                <div class="form-actions">
                    <button type="button" onclick="closeRuleModal()">Cancel</button>
                    <button type="submit">Save Rule</button>
                </div>
            </form>
        </div>
    </div>
    
    <script src="/static/js/rules.js"></script>
</body>
</html>
```

### Step 10: CSS Styling

```css
/* web/static/css/admin.css */
:root {
    --primary-color: #2563eb;
    --success-color: #16a34a;
    --warning-color: #ea580c;
    --danger-color: #dc2626;
    --background-color: #f8fafc;
    --sidebar-color: #1e293b;
    --border-color: #e2e8f0;
    --text-color: #334155;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: var(--background-color);
    color: var(--text-color);
}

.admin-container {
    display: flex;
    min-height: 100vh;
}

/* Sidebar */
.sidebar {
    width: 250px;
    background-color: var(--sidebar-color);
    color: white;
    padding: 0;
}

.sidebar-header {
    padding: 20px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.sidebar-header h3 {
    margin-bottom: 10px;
}

.connection-status {
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 500;
}

.connection-status.connected {
    background-color: var(--success-color);
}

.connection-status.disconnected {
    background-color: var(--danger-color);
}

.sidebar-menu {
    list-style: none;
    padding: 0;
}

.sidebar-menu li {
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.sidebar-menu a {
    display: block;
    padding: 15px 20px;
    color: rgba(255, 255, 255, 0.8);
    text-decoration: none;
    transition: all 0.3s ease;
}

.sidebar-menu a:hover,
.sidebar-menu a.active {
    background-color: rgba(255, 255, 255, 0.1);
    color: white;
}

.sidebar-footer {
    position: absolute;
    bottom: 0;
    width: 250px;
    padding: 20px;
    border-top: 1px solid rgba(255, 255, 255, 0.1);
}

/* Main Content */
.main-content {
    flex: 1;
    padding: 20px;
    overflow-y: auto;
}

.dashboard-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
}

.dashboard-header h1 {
    font-size: 2rem;
    font-weight: 600;
}

.last-updated {
    color: #64748b;
    font-size: 14px;
}

/* Metrics Grid */
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.metric-card {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    border-left: 4px solid var(--primary-color);
    display: flex;
    align-items: center;
    gap: 16px;
}

.metric-card.danger {
    border-left-color: var(--danger-color);
}

.metric-icon {
    font-size: 2rem;
}

.metric-value {
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--text-color);
}

.metric-label {
    font-size: 14px;
    color: #64748b;
    margin-top: 4px;
}

/* Charts */
.charts-grid {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 20px;
    margin-bottom: 30px;
}

.chart-container {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.chart-container h3 {
    margin-bottom: 20px;
    font-size: 1.25rem;
    font-weight: 600;
}

/* System Health */
.system-health {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    margin-bottom: 30px;
}

.health-metrics {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.health-item label {
    display: block;
    margin-bottom: 8px;
    font-weight: 500;
}

.progress-bar {
    position: relative;
    height: 20px;
    background-color: #e2e8f0;
    border-radius: 10px;
    overflow: hidden;
}

.progress-fill {
    height: 100%;
    border-radius: 10px;
    transition: width 0.3s ease;
}

.progress-fill.bg-success { background-color: var(--success-color); }
.progress-fill.bg-warning { background-color: var(--warning-color); }
.progress-fill.bg-danger { background-color: var(--danger-color); }

.progress-text {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-size: 12px;
    font-weight: 500;
    color: white;
    text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
}

/* Blocked IPs */
.blocked-ips {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.blocked-ips h3 {
    margin-bottom: 20px;
    font-size: 1.25rem;
    font-weight: 600;
}

.blocked-ips-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.blocked-ip-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px;
    background-color: #f8fafc;
    border-radius: 8px;
    border: 1px solid var(--border-color);
}

.blocked-ip-item .ip {
    font-family: 'Monaco', 'Menlo', monospace;
    font-weight: 500;
}

/* Rules Page Styles */
.page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
}

.rules-container {
    background: white;
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.rules-filters {
    padding: 20px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    gap: 16px;
}

.rules-filters select {
    padding: 8px 12px;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    font-size: 14px;
}

.rule-card {
    padding: 20px;
    border-bottom: 1px solid var(--border-color);
    transition: background-color 0.2s ease;
}

.rule-card:hover {
    background-color: #f8fafc;
}

.rule-card.disabled {
    opacity: 0.6;
}

.rule-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 12px;
}

.rule-info h4 {
    font-size: 1.125rem;
    font-weight: 600;
    margin-bottom: 8px;
}

.rule-category,
.rule-priority {
    display: inline-block;
    padding: 4px 8px;
    background-color: #e2e8f0;
    border-radius: 4px;
    font-size: 12px;
    margin-right: 8px;
}

.rule-actions {
    display: flex;
    align-items: center;
    gap: 12px;
}

.toggle-switch {
    position: relative;
    display: inline-block;
    width: 50px;
    height: 24px;
}

.toggle-switch input {
    opacity: 0;
    width: 0;
    height: 0;
}

.toggle-slider {
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: #ccc;
    transition: 0.4s;
    border-radius: 24px;
}

.toggle-slider:before {
    position: absolute;
    content: "";
    height: 18px;
    width: 18px;
    left: 3px;
    bottom: 3px;
    background-color: white;
    transition: 0.4s;
    border-radius: 50%;
}

input:checked + .toggle-slider {
    background-color: var(--primary-color);
}

input:checked + .toggle-slider:before {
    transform: translateX(26px);
}

.rule-description {
    color: #64748b;
    margin-bottom: 12px;
    line-height: 1.5;
}

.rule-conditions {
    margin-bottom: 12px;
}

.condition {
    background-color: #f1f5f9;
    padding: 8px 12px;
    border-radius: 6px;
    font-family: 'Monaco', 'Menlo', monospace;
    font-size: 14px;
    margin-top: 6px;
}

.action-badge {
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 500;
    text-transform: uppercase;
}

.action-block { background-color: #fecaca; color: #dc2626; }
.action-log { background-color: #fed7aa; color: #ea580c; }
.action-allow { background-color: #bbf7d0; color: #16a34a; }

/* Buttons */
.btn {
    padding: 8px 16px;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: all 0.2s ease;
}

.btn-primary {
    background-color: var(--primary-color);
    color: white;
}

.btn-primary:hover {
    background-color: #1d4ed8;
}

.btn-sm {
    padding: 4px 8px;
    font-size: 12px;
}

.btn-outline {
    background-color: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-color);
}

.btn-outline:hover {
    background-color: #f1f5f9;
}

.btn-outline-danger {
    border-color: var(--danger-color);
    color: var(--danger-color);
}

.btn-outline-danger:hover {
    background-color: #fef2f2;
}

/* Notifications */
.notification {
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 20px;
    border-radius: 6px;
    color: white;
    font-weight: 500;
    z-index: 1000;
    animation: slideInRight 0.3s ease;
}

.notification.success {
    background-color: var(--success-color);
}

.notification.error {
    background-color: var(--danger-color);
}

@keyframes slideInRight {
    from {
        transform: translateX(100%);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}

/* Modal Styles */
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5);
}

.modal-content {
    background-color: white;
    margin: 5% auto;
    padding: 30px;
    border-radius: 12px;
    width: 90%;
    max-width: 600px;
    position: relative;
}

.modal-close {
    position: absolute;
    top: 15px;
    right: 20px;
    font-size: 24px;
    cursor: pointer;
    color: #64748b;
}

.modal-close:hover {
    color: var(--text-color);
}

/* Form Styles */
.form-group {
    margin-bottom: 20px;
}

.form-row {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 16px;
}

.form-group label {
    display: block;
    margin-bottom: 6px;
    font-weight: 500;
}

.form-group input,
.form-group select,
.form-group textarea {
    width: 100%;
    padding: 8px 12px;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    font-size: 14px;
}

.form-group textarea {
    resize: vertical;
    min-height: 80px;
}

.form-actions {
    display: flex;
    gap: 12px;
    justify-content: flex-end;
    margin-top: 30px;
    padding-top: 20px;
    border-top: 1px solid var(--border-color);
}

/* Responsive Design */
@media (max-width: 768px) {
    .admin-container {
        flex-direction: column;
    }
    
    .sidebar {
        width: 100%;
        height: auto;
    }
    
    .sidebar-footer {
        position: static;
        width: 100%;
    }
    
    .metrics-grid {
        grid-template-columns: 1fr;
    }
    
    .charts-grid {
        grid-template-columns: 1fr;
    }
    
    .health-metrics {
        grid-template-columns: 1fr;
    }
    
    .form-row {
        grid-template-columns: 1fr;
    }
}
```

### Step 11: Rule Management API Handlers

```go
// internal/admin/api_handlers.go
package admin

import (
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "time"
    
    "your-project/internal/config"
)

// API Response structures
type APIResponse struct {
    Success bool        `json:"success"`
    Message string      `json:"message,omitempty"`
    Data    interface{} `json:"data,omitempty"`
    Error   string      `json:"error,omitempty"`
}

// Rule API handlers
func (s *AdminServer) handleAPIRules(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case "GET":
        s.handleGetRules(w, r)
    case "POST":
        s.handleCreateRule(w, r)
    case "PUT":
        s.handleUpdateRule(w, r)
    case "DELETE":
        s.handleDeleteRule(w, r)
    default:
        s.sendAPIError(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func (s *AdminServer) handleGetRules(w http.ResponseWriter, r *http.Request) {
    rules := s.configManager.GetRules()
    
    // Apply filters if provided
    category := r.URL.Query().Get("category")
    status := r.URL.Query().Get("status")
    
    var filteredRules []config.Rule
    for _, rule := range rules {
        // Category filter
        if category != "" && rule.Category != category {
            continue
        }
        
        // Status filter
        if status == "enabled" && !rule.Enabled {
            continue
        }
        if status == "disabled" && rule.Enabled {
            continue
        }
        
        filteredRules = append(filteredRules, rule)
    }
    
    s.sendAPISuccess(w, filteredRules)
}

func (s *AdminServer) handleCreateRule(w http.ResponseWriter, r *http.Request) {
    var rule config.Rule
    if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
        s.sendAPIError(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    // Generate ID if not provided
    if rule.ID == "" {
        rule.ID = fmt.Sprintf("rule_%d", time.Now().Unix())
    }
    
    // Validate rule
    if err := s.validateRule(&rule); err != nil {
        s.sendAPIError(w, fmt.Sprintf("Invalid rule: %v", err), http.StatusBadRequest)
        return
    }
    
    // Save rule to file
    if err := s.saveRuleToFile(&rule); err != nil {
        s.sendAPIError(w, fmt.Sprintf("Failed to save rule: %v", err), http.StatusInternalServerError)
        return
    }
    
    // Log the action
    s.logAuditAction(r.Context().Value("user").(string), "create_rule", rule.ID)
    
    s.sendAPISuccess(w, rule)
}

func (s *AdminServer) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
    ruleID := s.extractRuleIDFromPath(r.URL.Path)
    if ruleID == "" {
        s.sendAPIError(w, "Rule ID required", http.StatusBadRequest)
        return
    }
    
    var updatedRule config.Rule
    if err := json.NewDecoder(r.Body).Decode(&updatedRule); err != nil {
        s.sendAPIError(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    updatedRule.ID = ruleID
    
    // Validate rule
    if err := s.validateRule(&updatedRule); err != nil {
        s.sendAPIError(w, fmt.Sprintf("Invalid rule: %v", err), http.StatusBadRequest)
        return
    }
    
    // Update rule file
    if err := s.updateRuleInFile(&updatedRule); err != nil {
        s.sendAPIError(w, fmt.Sprintf("Failed to update rule: %v", err), http.StatusInternalServerError)
        return
    }
    
    // Log the action
    s.logAuditAction(r.Context().Value("user").(string), "update_rule", ruleID)
    
    s.sendAPISuccess(w, updatedRule)
}

func (s *AdminServer) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
    ruleID := s.extractRuleIDFromPath(r.URL.Path)
    if ruleID == "" {
        s.sendAPIError(w, "Rule ID required", http.StatusBadRequest)
        return
    }
    
    // Remove rule from file
    if err := s.removeRuleFromFile(ruleID); err != nil {
        s.sendAPIError(w, fmt.Sprintf("Failed to delete rule: %v", err), http.StatusInternalServerError)
        return
    }
    
    // Log the action
    s.logAuditAction(r.Context().Value("user").(string), "delete_rule", ruleID)
    
    s.sendAPISuccess(w, map[string]string{"message": "Rule deleted successfully"})
}

// Helper functions for rule management
func (s *AdminServer) validateRule(rule *config.Rule) error {
    if rule.ID == "" {
        return fmt.Errorf("rule ID cannot be empty")
    }
    
    if rule.Name == "" {
        return fmt.Errorf("rule name cannot be empty")
    }
    
    validActions := map[string]bool{
        "allow": true, "block": true, "log": true,
    }
    
    if !validActions[rule.Action] {
        return fmt.Errorf("invalid action: %s", rule.Action)
    }
    
    if rule.Priority < 1 || rule.Priority > 1000 {
        return fmt.Errorf("priority must be between 1 and 1000")
    }
    
    // Validate conditions
    for _, condition := range rule.Conditions {
        if condition.Field == "" || condition.Operator == "" || condition.Value == "" {
            return fmt.Errorf("condition fields cannot be empty")
        }
        
        validFields := map[string]bool{
            "url": true, "body": true, "header": true, "method": true, "ip": true,
        }
        
        if !validFields[condition.Field] {
            return fmt.Errorf("invalid condition field: %s", condition.Field)
        }
        
        validOperators := map[string]bool{
            "contains": true, "regex": true, "equals": true, "starts_with": true, "ends_with": true,
        }
        
        if !validOperators[condition.Operator] {
            return fmt.Errorf("invalid condition operator: %s", condition.Operator)
        }
    }
    
    return nil
}

func (s *AdminServer) extractRuleIDFromPath(path string) string {
    parts := strings.Split(path, "/")
    if len(parts) >= 4 && parts[2] == "rules" {
        return parts[3]
    }
    return ""
}

// API utility functions
func (s *AdminServer) sendAPISuccess(w http.ResponseWriter, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(APIResponse{
        Success: true,
        Data:    data,
    })
}

func (s *AdminServer) sendAPIError(w http.ResponseWriter, message string, statusCode int) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(APIResponse{
        Success: false,
        Error:   message,
    })
}

// Configuration API handlers
func (s *AdminServer) handleAPIConfig(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case "GET":
        config := s.configManager.GetConfig()
        s.sendAPISuccess(w, config)
        
    case "POST":
        var newConfig config.WAFConfig
        if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
            s.sendAPIError(w, "Invalid JSON", http.StatusBadRequest)
            return
        }
        
        // Validate configuration
        if err := s.validateConfiguration(&newConfig); err != nil {
            s.sendAPIError(w, fmt.Sprintf("Invalid configuration: %v", err), http.StatusBadRequest)
            return
        }
        
        // Save configuration
        if err := s.saveConfiguration(&newConfig); err != nil {
            s.sendAPIError(w, fmt.Sprintf("Failed to save configuration: %v", err), http.StatusInternalServerError)
            return
        }
        
        // Log the action
        s.logAuditAction(r.Context().Value("user").(string), "update_config", "main")
        
        s.sendAPISuccess(w, newConfig)
        
    default:
        s.sendAPIError(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func (s *AdminServer) validateConfiguration(config *config.WAFConfig) error {
    if config.Server.Port <= 0 || config.Server.Port > 65535 {
        return fmt.Errorf("invalid server port: %d", config.Server.Port)
    }
    
    if config.Engine.MaxBodySize <= 0 {
        return fmt.Errorf("max_body_size must be positive")
    }
    
    if config.RateLimit.RequestsPerMinute <= 0 {
        return fmt.Errorf("requests_per_minute must be positive")
    }
    
    return nil
}

// Audit logging
func (s *AdminServer) logAuditAction(user, action, target string) {
    auditLog := map[string]interface{}{
        "timestamp": time.Now().ISO8601(),
        "user":      user,
        "action":    action,
        "target":    target,
        "ip":        "", // Would get from request context
    }
    
    // In a real implementation, save to audit log file or database
    fmt.Printf("AUDIT: %+v\n", auditLog)
}
```

### Step 12: Integration with WAF Engine

```go
// internal/admin/waf_integration.go
package admin

import (
    "context"
    "fmt"
    "regexp"
    
    "your-project/internal/config"
    "your-project/internal/core/engine"
    "your-project/pkg/models"
)

// DynamicFilter represents a filter created from configuration rules
type DynamicFilter struct {
    rule       config.Rule
    conditions []*FilterCondition
}

type FilterCondition struct {
    field    string
    operator string
    value    string
    negate   bool
    regex    *regexp.Regexp // Pre-compiled for performance
}

func NewDynamicFilter(rule config.Rule) (*DynamicFilter, error) {
    filter := &DynamicFilter{
        rule:       rule,
        conditions: make([]*FilterCondition, 0, len(rule.Conditions)),
    }
    
    // Convert rule conditions to filter conditions
    for _, ruleCondition := range rule.Conditions {
        filterCondition := &FilterCondition{
            field:    ruleCondition.Field,
            operator: ruleCondition.Operator,
            value:    ruleCondition.Value,
            negate:   ruleCondition.Negate,
        }
        
        // Pre-compile regex patterns for performance
        if ruleCondition.Operator == "regex" {
            regex, err := regexp.Compile(ruleCondition.Value)
            if err != nil {
                return nil, fmt.Errorf("invalid regex pattern in rule %s: %w", rule.ID, err)
            }
            filterCondition.regex = regex
        }
        
        filter.conditions = append(filter.conditions, filterCondition)
    }
    
    return filter, nil
}

func (f *DynamicFilter) Name() string {
    return f.rule.ID
}

func (f *DynamicFilter) Priority() int {
    return f.rule.Priority
}

func (f *DynamicFilter) Process(ctx context.Context, req *models.FilterRequest) (*models.FilterResponse, error) {
    // Skip if rule is disabled
    if !f.rule.Enabled {
        return &models.FilterResponse{Action: models.ActionAllow}, nil
    }
    
    // Check all conditions (AND logic)
    allConditionsMet := true
    
    for _, condition := range f.conditions {
        conditionMet := f.checkCondition(condition, req)
        
        // Apply negation if specified
        if condition.negate {
            conditionMet = !conditionMet
        }
        
        if !conditionMet {
            allConditionsMet = false
            break
        }
    }
    
    // If all conditions are met, apply the rule action
    if allConditionsMet {
        action := f.convertAction(f.rule.Action)
        
        return &models.FilterResponse{
            Action:      action,
            RuleMatched: f.rule.ID,
            Reason:      f.rule.Description,
            Metadata: map[string]any{
                "rule_name": f.rule.Name,
                "category":  f.rule.Category,
                "priority":  f.rule.Priority,
            },
        }, nil
    }
    
    return &models.FilterResponse{Action: models.ActionAllow}, nil
}

func (f *DynamicFilter) checkCondition(condition *FilterCondition, req *models.FilterRequest) bool {
    var fieldValue string
    
    // Extract field value from request
    switch condition.field {
    case "url":
        fieldValue = req.Request.URL.String()
    case "body":
        fieldValue = string(req.Body)
    case "method":
        fieldValue = req.Request.Method
    case "ip":
        fieldValue = req.ClientIP
    case "header":
        // For headers, we need to check all header values
        for _, values := range req.Request.Header {
            for _, value := range values {
                if f.matchValue(condition, value) {
                    return true
                }
            }
        }
        return false
    default:
        return false
    }
    
    return f.matchValue(condition, fieldValue)
}

func (f *DynamicFilter) matchValue(condition *FilterCondition, value string) bool {
    switch condition.operator {
    case "equals":
        return value == condition.value
    case "contains":
        return strings.Contains(strings.ToLower(value), strings.ToLower(condition.value))
    case "starts_with":
        return strings.HasPrefix(strings.ToLower(value), strings.ToLower(condition.value))
    case "ends_with":
        return strings.HasSuffix(strings.ToLower(value), strings.ToLower(condition.value))
    case "regex":
        if condition.regex != nil {
            return condition.regex.MatchString(value)
        }
        return false
    default:
        return false
    }
}

func (f *DynamicFilter) convertAction(action string) models.Action {
    switch action {
    case "block":
        return models.ActionBlock
    case "log":
        return models.ActionLog
    case "allow":
        return models.ActionAllow
    default:
        return models.ActionAllow
    }
}

// RuleManager handles dynamic rule updates in the WAF engine
type RuleManager struct {
    engine      *engine.WAFEngine
    activeRules map[string]*DynamicFilter
}

func NewRuleManager(engine *engine.WAFEngine) *RuleManager {
    return &RuleManager{
        engine:      engine,
        activeRules: make(map[string]*DynamicFilter),
    }
}

func (rm *RuleManager) UpdateRules(rules []config.Rule) error {
    // Remove all existing dynamic rules
    for ruleID := range rm.activeRules {
        rm.engine.RemoveFilter(ruleID)
        delete(rm.activeRules, ruleID)
    }
    
    // Add new rules
    for _, rule := range rules {
        if rule.Enabled {
            filter, err := NewDynamicFilter(rule)
            if err != nil {
                return fmt.Errorf("failed to create filter for rule %s: %w", rule.ID, err)
            }
            
            rm.engine.AddFilter(filter)
            rm.activeRules[rule.ID] = filter
        }
    }
    
    fmt.Printf("Updated rules: %d active rules loaded\n", len(rm.activeRules))
    return nil
}
```

### Step 13: Complete Integration Example

```go
// cmd/admin/main.go
package main

import (
    "fmt"
    "log"
    
    "your-project/internal/admin"
    "your-project/internal/config"
    "your-project/internal/core/engine"
)

func main() {
    // Load configuration
    configManager, err := config.NewConfigManager("configs/waf.yaml")
    if err != nil {
        log.Fatalf("Failed to load configuration: %v", err)
    }
    
    // Create WAF engine (this would normally be running in a separate process)
    wafEngine := engine.NewWAFEngine(10*1024*1024, 5*time.Second)
    
    // Create rule manager for dynamic rule updates
    ruleManager := admin.NewRuleManager(wafEngine)
    
    // Set up configuration change callbacks
    configManager.OnRulesChange(func(rules []config.Rule) {
        fmt.Println("Rules changed, updating WAF engine...")
        if err := ruleManager.UpdateRules(rules); err != nil {
            fmt.Printf("Failed to update rules: %v\n", err)
        }
    })
    
    // Load initial rules
    rules := configManager.GetRules()
    if err := ruleManager.UpdateRules(rules); err != nil {
        log.Fatalf("Failed to load initial rules: %v", err)
    }
    
    // Start configuration file watching
    if err := configManager.StartWatching(); err != nil {
        log.Fatalf("Failed to start config watcher: %v", err)
    }
    
    // Create and start admin server
    adminConfig := configManager.GetConfig().Admin
    adminServer := admin.NewAdminServer(&adminConfig, configManager, wafEngine)
    
    // Start metrics hub for real-time updates
    adminServer.GetMetricsHub().Start()
    
    fmt.Printf("Starting admin server on %s:%d\n", adminConfig.Host, adminConfig.Port)
    log.Fatal(adminServer.Start())
}
```

## Key Learning Concepts Mastered

### 1. **Web Application Architecture**
- Separation of concerns (API vs UI)
- Real-time communication with WebSockets
- RESTful API design principles

### 2. **Configuration Management**
- Hot-reload mechanisms
- File watching and event handling
- YAML-based configuration systems
- Configuration validation

### 3. **Dynamic System Behavior**
- Runtime rule updates
- Filter chain modification
- State management in web applications

### 4. **Frontend Integration**
- Real-time dashboard updates
- Chart.js for data visualization
- Modern CSS layout techniques
- JavaScript event handling

### 5. **Security Patterns**
- JWT-based authentication
- Role-based access control
- Audit logging
- Input validation and sanitization

## Testing Your Phase 2 Implementation

### 1. **Start the Services**
```bash
# Terminal 1: Start WAF engine
go run cmd/waf/main.go

# Terminal 2: Start admin panel
go run cmd/admin/main.go

# Terminal 3: Start test backend
go run test/backend/main.go
```

### 2. **Test Admin Interface**
- Visit `http://localhost:8081` (admin panel)
- Login with configured credentials
- Watch real-time metrics
- Create/edit rules
- Test configuration updates

### 3. **Test Rule Creation**
Create a test rule via the API:
```bash
curl -X POST http://localhost:8081/api/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "Test SQL Injection Rule",
    "description": "Blocks basic SQL injection attempts",
    "category": "sql_injection",
    "enabled": true,
    "priority": 100,
    "action": "block",
    "conditions": [
      {
        "field": "url",
        "operator": "contains",
        "value": "UNION SELECT"
      }
    ]
  }'
```

This Phase 2 implementation gives you a complete admin interface with real-time monitoring, dynamic configuration management, and a solid foundation for managing your WAF system. The modular architecture makes it easy to extend with additional features in future phases.