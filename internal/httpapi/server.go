// Package httpapi implements the threat exchange HTTP boundary and its protections.
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
	"threat-exchange/internal/api"
	"threat-exchange/internal/threat"
)

// Repository is the storage contract; implementations must support concurrent calls.
type Repository interface {
	Get(context.Context, string) (threat.Threat, error)
	Create(context.Context, threat.Threat) (threat.Threat, error)
	Update(context.Context, threat.Threat) (threat.Threat, error)
	Ping(context.Context) error
}

// Options defines immutable authentication, admission and logging configuration.
type Options struct {
	Token  string
	RPS    float64
	Burst  int
	Logger *slog.Logger
}

type server struct {
	repo   Repository
	logger *slog.Logger
}

// New builds the handler. Health checks bypass authentication and rate limiting.
func New(repo Repository, options Options) (http.Handler, error) {
	if repo == nil || len(options.Token) < 32 || options.RPS <= 0 || math.IsNaN(options.RPS) || math.IsInf(options.RPS, 0) || options.Burst < 1 {
		return nil, fmt.Errorf("invalid HTTP options")
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	s := &server{repo: repo, logger: options.Logger}
	mux := http.NewServeMux()
	mux.HandleFunc("/info", s.collection)
	mux.HandleFunc("/info/{md5}", s.record)
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { writeError(w, 404, "Route not found", "") })
	expected := sha256.Sum256([]byte(options.Token))
	limiter := rate.NewLimiter(rate.Limit(options.RPS), options.Burst)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		defer func() {
			if recover() != nil {
				s.logger.Error("HTTP handler panicked")
				writeError(w, 500, "Internal server error", "")
			}
		}()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		if r.URL.Path != "/healthz" {
			if !limiter.Allow() {
				retry := math.Max(1, math.Ceil(1/options.RPS))
				if math.IsInf(retry, 0) {
					retry = math.MaxFloat64
				}
				w.Header().Set("Retry-After", strconv.FormatFloat(retry, 'f', 0, 64))
				writeError(w, 429, "Rate limit exceeded", "")
				return
			}
			auth := r.Header.Get("Authorization")
			provided := ""
			if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
				provided = auth[7:]
			}
			digest := sha256.Sum256([]byte(provided))
			if len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare(expected[:], digest[:]) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="threat-exchange"`)
				writeError(w, 401, "Unauthorized", "")
				return
			}
		}
		mux.ServeHTTP(w, r)
	}), nil
}

func (s *server) collection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var req api.ThreatCreateRequest
	if err := decodeObject(w, r, &req); err != nil {
		respondInputError(w, err)
		return
	}
	input, err := makeInput(req.Name, req.Description, req.Category, req.Severity, req.FirstSeen)
	if err != nil {
		writeError(w, 400, "Invalid request", err.Error())
		return
	}
	item, err := threat.Validate(req.Md5, input, time.Now())
	if err != nil {
		writeError(w, 400, "Invalid request", err.Error())
		return
	}
	item, err = s.repo.Create(r.Context(), item)
	if err != nil {
		s.storageError(w, err)
		return
	}
	w.Header().Set("Location", "/info/"+item.MD5)
	writeJSON(w, 201, response(item))
}

func (s *server) record(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		methodNotAllowed(w, "GET, PUT")
		return
	}
	md5, err := threat.NormalizeMD5(r.PathValue("md5"))
	if err != nil {
		writeError(w, 400, "Invalid MD5", err.Error())
		return
	}
	if r.Method == http.MethodGet {
		item, err := s.repo.Get(r.Context(), md5)
		if err != nil {
			s.storageError(w, err)
			return
		}
		writeJSON(w, 200, response(item))
		return
	}
	var req api.ThreatUpdateRequest
	if err := decodeObject(w, r, &req); err != nil {
		respondInputError(w, err)
		return
	}
	input, err := makeInput(req.Name, req.Description, req.Category, req.Severity, req.FirstSeen)
	if err != nil {
		writeError(w, 400, "Invalid request", err.Error())
		return
	}
	item, err := threat.Validate(md5, input, time.Now())
	if err != nil {
		writeError(w, 400, "Invalid request", err.Error())
		return
	}
	item, err = s.repo.Update(r.Context(), item)
	if err != nil {
		s.storageError(w, err)
		return
	}
	writeJSON(w, 200, response(item))
}

func makeInput(name string, description *string, category *api.Category, severity *api.Severity, first *time.Time) (threat.Input, error) {
	input := threat.Input{Name: name, FirstSeen: first}
	if description != nil {
		input.Description = *description
	}
	if category != nil {
		if *category == "" {
			return input, errors.New("category must not be empty")
		}
		input.Category = string(*category)
	}
	if severity != nil {
		if *severity == "" {
			return input, errors.New("severity must not be empty")
		}
		input.Severity = string(*severity)
	}
	return input, nil
}

func response(item threat.Threat) api.ThreatResponse {
	return api.ThreatResponse{Md5: item.MD5, Name: item.Name, Description: item.Description, Category: api.Category(item.Category), Severity: api.Severity(item.Severity), FirstSeen: item.FirstSeen, CreatedAt: &item.CreatedAt, UpdatedAt: &item.UpdatedAt}
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if err := s.repo.Ping(r.Context()); err != nil {
		writeError(w, 503, "Service unavailable", "")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *server) storageError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, threat.ErrNotFound):
		writeError(w, 404, "Threat not found", "")
	case errors.Is(err, threat.ErrConflict):
		writeError(w, 409, "Threat already exists", "")
	default:
		s.logger.Error("database operation failed", "error", err)
		writeError(w, 500, "Internal server error", "")
	}
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, 405, "Method not allowed", "")
}
func respondInputError(w http.ResponseWriter, err error) {
	var input *inputError
	if errors.As(err, &input) {
		writeError(w, input.status, http.StatusText(input.status), input.details)
		return
	}
	writeError(w, 400, "Invalid request", "")
}
func writeError(w http.ResponseWriter, status int, message, details string) {
	body := api.ErrorResponse{Message: message}
	if details != "" {
		body.Details = &details
	}
	writeJSON(w, status, body)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
