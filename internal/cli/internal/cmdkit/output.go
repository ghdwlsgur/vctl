package cmdkit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type Format string

const (
	OutputTable Format = "table"
	OutputJSON  Format = "json"
	OutputYAML  Format = "yaml"

	StructuredOutputAnnotation = "vctl.output.structured"
)

// SupportsStructuredOutput marks the commands whose result has a stable data
// shape. The root validates -o before the command opens Vault or Postgres, so a
// command can never silently print a human table after accepting -o json.
func SupportsStructuredOutput(cmd *cobra.Command) *cobra.Command {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[StructuredOutputAnnotation] = "true"
	return cmd
}

func ValidateOutputSelection(cmd *cobra.Command) error {
	format, err := RequestedOutput(cmd)
	if err != nil {
		return err
	}
	if format != OutputTable && cmd.Annotations[StructuredOutputAnnotation] != "true" {
		return fmt.Errorf("%s does not support --output %s", cmd.CommandPath(), format)
	}
	return nil
}

func RequestedOutput(cmd *cobra.Command) (Format, error) {
	raw, err := cmd.Flags().GetString("output")
	if err != nil || raw == "" {
		raw = string(OutputTable)
	}
	format := Format(strings.ToLower(raw))
	switch format {
	case OutputTable, OutputJSON, OutputYAML:
		return format, nil
	default:
		return "", fmt.Errorf("unsupported output %q; choose table, json, or yaml", raw)
	}
}

// CommandOutput translates the old --json switch at the compatibility seam.
// New callers use -o; existing scripts keep getting byte-for-byte JSON.
func CommandOutput(cmd *cobra.Command, legacyJSON bool) (Format, error) {
	format, err := RequestedOutput(cmd)
	if err != nil {
		return "", err
	}
	if legacyJSON {
		if cmd.Flags().Changed("output") && format != OutputJSON {
			return "", fmt.Errorf("--json and --output %s cannot be used together", format)
		}
		return OutputJSON, nil
	}
	return format, nil
}

func WriteStructured(format Format, value any) error {
	return encodeStructured(os.Stdout, format, value)
}

func encodeStructured(w io.Writer, format Format, value any) error {
	switch format {
	case OutputJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	case OutputYAML:
		// Marshal through JSON so YAML is a second encoding of the same public
		// data contract, including json field names and omitempty behaviour.
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		var document any
		if err := json.Unmarshal(data, &document); err != nil {
			return err
		}
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		if err := enc.Encode(document); err != nil {
			return err
		}
		// Close flushes; a dropped error here is a truncated document that
		// looked like a success.
		return enc.Close()
	default:
		return fmt.Errorf("output %q is not structured", format)
	}
}
