package main

import (
	"context"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/caarlos0/sshsig"
	"github.com/charmbracelet/fang"
	"github.com/charmbracelet/x/exp/charmtone"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const namespace = "ssign@becker.software"

func main() {
	cmd := &cobra.Command{
		Use:   "ssign",
		Short: "sign and verify files using SSH signatures",
		Example: `ssign sign --key ./id_ed25519 file file.sig
ssign verify --public-key ./id_ed25519.pub file file.sig`,
	}

	var keyPath string
	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a file",
		Args:  cobra.RangeArgs(1, 2),
		Example: `ssign sign README.md
ssign sign --key id_ed25519 README.md README.sig`,
		Aliases: []string{"s"},
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := openPrivateKey(keyPath)
			if err != nil {
				return fmt.Errorf("key %s: %w", keyPath, err)
			}

			signer, ok := key.(ssh.AlgorithmSigner)
			if !ok {
				return fmt.Errorf("cannot use this key")
			}

			message, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("could open file %s: %w", args[0], err)
			}

			data, err := sshsig.Sign(signer, rand.Reader, message, namespace)
			if err != nil {
				return fmt.Errorf("could not sign: %w", err)
			}

			var sigName string
			if len(args) > 1 {
				sigName = args[1]
			} else {
				sigName = args[0] + ".ssig"
			}

			if err := os.WriteFile(sigName, data, 0o644); err != nil {
				return fmt.Errorf("could not write signature %s: %w", sigName, err)
			}

			styles := mustStyles()
			cmd.Println(styles.Header.String())
			cmd.Println(styles.Text.Render(
				"Signed " +
					styles.Code.Render(args[0]) +
					" with " +
					styles.Code.Render(keyPath) +
					".",
			))
			cmd.Println(styles.Text.Render(
				"Signature stored at " +
					styles.Code.Render(sigName) +
					".",
			))
			return nil
		},
	}
	signCmd.PersistentFlags().StringVar(&keyPath, "key", os.ExpandEnv("$HOME/.ssh/id_ed25519"), "SSH Key to be used")

	var pubkeyPath string
	verifyCmd := &cobra.Command{
		Use:   "verify [signature]",
		Short: "Verify a signature",
		Example: `ssign verify README.md
ssign verify --public-key id_ed25519.pub README.md README.md.ssig`,
		Aliases: []string{"v"},
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, err := openPublicKey(pubkeyPath)
			if err != nil {
				return fmt.Errorf("could not parse public key %s: %w", pubkeyPath, err)
			}

			message, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("could not open subject: %w", err)
			}

			var sigName string
			if len(args) > 1 {
				sigName = args[1]
			} else {
				sigName = args[0] + ".ssig"
			}
			signature, err := os.ReadFile(sigName)
			if err != nil {
				return fmt.Errorf("could not open signature: %w", err)
			}

			block, _ := pem.Decode(signature)

			if err := sshsig.Verify(pub, message, block.Bytes, namespace); err != nil {
				return fmt.Errorf("could not verify: %w", err)
			}

			styles := mustStyles()
			cmd.Println(styles.Header.String())
			cmd.Println(styles.Text.Render(
				"Valid signature for " +
					styles.Code.Render(args[0]) +
					" at " +
					styles.Code.Render(sigName) +
					".",
			))
			cmd.Println(styles.Text.Render(
				"Verified signed for key " +
					styles.Code.Render(pubkeyPath) +
					".",
			))
			return nil
		},
	}
	verifyCmd.PersistentFlags().StringVar(&pubkeyPath, "public-key", os.ExpandEnv("$HOME/.ssh/id_ed25519.pub"), "SSH public key to be used")

	cmd.AddCommand(signCmd, verifyCmd)

	if err := fang.Execute(context.Background(), cmd); err != nil {
		os.Exit(1)
	}
}

type styles struct {
	Header lipgloss.Style
	Text   lipgloss.Style
	Code   lipgloss.Style
}

func mustStyles() styles {
	return styles{
		Code: lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(charmtone.Coral).
			Background(charmtone.Charcoal),
		Text: lipgloss.NewStyle().
			MarginLeft(2),
		Header: lipgloss.NewStyle().
			Foreground(charmtone.Squid).
			Background(charmtone.Julep).
			Bold(true).
			Padding(0, 1).
			Margin(1).
			MarginLeft(2).
			SetString("DONE!"),
	}
}

func openPublicKey(name string) (ssh.PublicKey, error) {
	in, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(in)
	if err == nil {
		return pub, nil
	}
	return ssh.ParsePublicKey(in)
}

func openPrivateKey(name string) (ssh.Signer, error) {
	pemBytes, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("key %s: %w", name, err)
	}
	result, err := ssh.ParsePrivateKey(pemBytes)
	if isPassphraseMissing(err) {
		passphrase, err := ask(name)
		if err != nil {
			return result, fmt.Errorf("key: %w", err)
		}
		result, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)
		if err != nil {
			return result, fmt.Errorf("key: %w", err)
		}
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("key: %w", err)
	}
	return result, nil
}

func isPassphraseMissing(err error) bool {
	var kerr *ssh.PassphraseMissingError
	return errors.As(err, &kerr)
}

func ask(path string) ([]byte, error) {
	var pass string
	if err := huh.Run(
		huh.NewInput().
			Inline(true).
			Value(&pass).
			Title(fmt.Sprintf("Enter the passphrase to unlock %q: ", path)).
			EchoMode(huh.EchoModePassword),
	); err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	return []byte(pass), nil
}
