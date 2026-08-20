package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type outputFormat string

const (
	outputTable outputFormat = "table"
	outputJSON  outputFormat = "json"
	outputYAML  outputFormat = "yaml"

	structuredOutputAnnotation = "vctl.output.structured"
)

// supportsStructuredOutput marks the commands whose result has a stable data
// shape. The root validates -o before the command opens Vault or Postgres, so a
// command can never silently print a human table after accepting -o json.
func supportsStructuredOutput(cmd *cobra.Command) *cobra.Command {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[structuredOutputAnnotation] = "true"
	return cmd
}

func validateOutputSelection(cmd *cobra.Command) error {
	format, err := requestedOutput(cmd)
	if err != nil {
		return err
	}
	if format != outputTable && cmd.Annotations[structuredOutputAnnotation] != "true" {
		return fmt.Errorf("%s does not support --output %s", cmd.CommandPath(), format)
	}
	return nil
}

func requestedOutput(cmd *cobra.Command) (outputFormat, error) {
	raw, err := cmd.Flags().GetString("output")
	if err != nil || raw == "" {
		raw = string(outputTable)
	}
	format := outputFormat(strings.ToLower(raw))
	switch format {
	case outputTable, outputJSON, outputYAML:
		return format, nil
	default:
		return "", fmt.Errorf("unsupported output %q; choose table, json, or yaml", raw)
	}
}

// commandOutput translates the old --json switch at the compatibility seam.
// New callers use -o; existing scripts keep getting byte-for-byte JSON.
func commandOutput(cmd *cobra.Command, legacyJSON bool) (outputFormat, error) {
	format, err := requestedOutput(cmd)
	if err != nil {
		return "", err
	}
	if legacyJSON {
		if cmd.Flags().Changed("output") && format != outputJSON {
			return "", fmt.Errorf("--json and --output %s cannot be used together", format)
		}
		return outputJSON, nil
	}
	return format, nil
}

func writeStructured(format outputFormat, value any) error {
	return encodeStructured(os.Stdout, format, value)
}

func encodeStructured(w io.Writer, format outputFormat, value any) error {
	switch format {
	case outputJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	case outputYAML:
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
		defer enc.Close()
		return enc.Encode(document)
	default:
		return fmt.Errorf("output %q is not structured", format)
	}
}
