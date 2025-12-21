// Package logger provides structured logging for TorForge
package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
)

var (
	// Log is the global logger instance
	Log zerolog.Logger
	
	// AuditLog is for security audit events
	AuditLog zerolog.Logger
)

// Config configures the logger
type Config struct {
	Level       string // debug, info, warn, error
	Console     bool   // Pretty console output
	File        string // Log file path
	AuditFile   string // Audit log file path (JSONL)
	JSONFormat  bool   // Use JSON format
}

// Init initializes the global logger
func Init(cfg Config) error {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(level)
	zerolog.TimeFieldFormat = time.RFC3339

	var writers []io.Writer

	// Console output
	if cfg.Console {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: "15:04:05",
			FormatLevel: func(i interface{}) string {
				return colorLevel(i)
			},
			FormatMessage: func(i interface{}) string {
				return fmt.Sprintf("| %s", i)
			},
		}
		writers = append(writers, consoleWriter)
	}

	// File output
	if cfg.File != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.File), 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
		file, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		writers = append(writers, file)
	}

	// Default to stderr if no writers
	if len(writers) == 0 {
		writers = append(writers, os.Stderr)
	}

	multi := zerolog.MultiLevelWriter(writers...)
	Log = zerolog.New(multi).With().Timestamp().Caller().Logger()

	// Audit log (always JSON, always to file)
	if cfg.AuditFile != "" {
		if err := initAuditLog(cfg.AuditFile); err != nil {
			return fmt.Errorf("failed to init audit log: %w", err)
		}
	} else {
		AuditLog = zerolog.Nop()
	}

	return nil
}

func initAuditLog(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	AuditLog = zerolog.New(file).With().Timestamp().Logger()
	return nil
}

func colorLevel(i interface{}) string {
	level, ok := i.(string)
	if !ok {
		return "???"
	}
	
	switch level {
	case "debug":
		return "\033[36mDBG\033[0m"  // Cyan
	case "info":
		return "\033[32mINF\033[0m"  // Green
	case "warn":
		return "\033[33mWRN\033[0m"  // Yellow
	case "error":
		return "\033[31mERR\033[0m"  // Red
	case "fatal":
		return "\033[35mFTL\033[0m"  // Magenta
	case "panic":
		return "\033[35mPNC\033[0m"  // Magenta
	default:
		return level
	}
}

// Debug logs a debug message
func Debug() *zerolog.Event {
	return Log.Debug()
}

// Info logs an info message
func Info() *zerolog.Event {
	return Log.Info()
}

// Warn logs a warning message
func Warn() *zerolog.Event {
	return Log.Warn()
}

// Error logs an error message
func Error() *zerolog.Event {
	return Log.Error()
}

// Fatal logs a fatal message and exits
func Fatal() *zerolog.Event {
	return Log.Fatal()
}

// Audit logs a security audit event
func Audit(event string) *zerolog.Event {
	return AuditLog.Info().Str("audit_event", event)
}

// WithComponent returns a logger with component context
func WithComponent(component string) zerolog.Logger {
	return Log.With().Str("component", component).Logger()
}

// CircuitEvent logs circuit-related events
func CircuitEvent(circuitID string, event string) {
	Log.Info().
		Str("circuit_id", circuitID).
		Str("event", event).
		Msg("circuit event")
	
	Audit("circuit").
		Str("circuit_id", circuitID).
		Str("event", event).
		Msg("")
}

// ConnectionEvent logs connection events
func ConnectionEvent(srcIP, dstIP string, dstPort int, action string) {
	Log.Debug().
		Str("src_ip", srcIP).
		Str("dst_ip", dstIP).
		Int("dst_port", dstPort).
		Str("action", action).
		Msg("connection")
}

// SecurityEvent logs security-related events
func SecurityEvent(event, details string) {
	Log.Warn().
		Str("security_event", event).
		Str("details", details).
		Msg("security alert")
	
	Audit("security").
		Str("event", event).
		Str("details", details).
		Msg("")
}

// LeakEvent logs potential leak events
func LeakEvent(leakType, destination string) {
	Log.Error().
		Str("leak_type", leakType).
		Str("destination", destination).
		Msg("POTENTIAL LEAK DETECTED")
	
	Audit("leak").
		Str("type", leakType).
		Str("destination", destination).
		Msg("")
}
