// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package cmd

import (
	"context"
	"fmt"
	"os"

	// Import the plugin so that it can register itself with the OPA runtime on init
	"github.com/godaddy/opa-lambda-extension-plugin/plugins/lambda"
	"github.com/spf13/cobra"
)

func init() {
	cmdParams := newRunParams()

	runCommand := &cobra.Command{
		Use:   "lambda-run",
		Short: "Start OPA in interactive or server mode",
		Long: `Start an instance of the Open Policy Agent (OPA).

To run the interactive shell:

    $ opa run

To run the server:

    $ opa run -s

The 'run' command starts an instance of the OPA runtime. The OPA runtime can be
started as an interactive shell or a server.

When the runtime is started as a shell, users can define rules and evaluate
expressions interactively. When the runtime is started as a server, OPA exposes
an HTTP API for managing policies, reading and writing data, and executing
queries.

The runtime can be initialized with one or more files that contain policies or
data. If the '--bundle' option is specified the paths will be treated as policy
bundles and loaded following standard bundle conventions. The path can be a
compressed archive file or a directory which will be treated as a bundle.
Without the '--bundle' flag OPA will recursively load ALL rego, JSON, and YAML
files.

When loading from directories, only files with known extensions are considered.
The current set of file extensions that OPA will consider are:

    .json          # JSON data
    .yaml or .yml  # YAML data
    .rego          # Rego file

Non-bundle data file and directory paths can be prefixed with the desired
destination in the data document with the following syntax:

    <dotted-path>:<file-path>

To set a data file as the input document in the interactive shell use the
"repl.input" path prefix with the input file:

    repl.input:<file-path>

Example:

    $ opa run repl.input:input.json

Which will load the "input.json" file at path "data.repl.input".

Use the "help input" command in the interactive shell to see more options.


File paths can be specified as URLs to resolve ambiguity in paths containing colons:

    $ opa run file:///c:/path/to/data.json

The 'run' command can also verify the signature of a signed bundle.
A signed bundle is a normal OPA bundle that includes a file
named ".signatures.json". For more information on signed bundles
see https://www.openpolicyagent.org/docs/latest/management-bundles/#signing.

The key to verify the signature of signed bundle can be provided
using the --verification-key flag. For example, for RSA family of algorithms,
the command expects a PEM file containing the public key.
For HMAC family of algorithms (eg. HS256), the secret can be provided
using the --verification-key flag.

The --verification-key-id flag can be used to optionally specify a name for the
key provided using the --verification-key flag.

The --signing-alg flag can be used to specify the signing algorithm.
The 'run' command uses RS256 (by default) as the signing algorithm.

The --scope flag can be used to specify the scope to use for
bundle signature verification.

Example:

    $ opa run --verification-key secret --signing-alg HS256 --bundle bundle.tar.gz

The 'run' command will read the bundle "bundle.tar.gz", check the
".signatures.json" file and perform verification using the provided key.
An error will be generated if "bundle.tar.gz" does not contain a ".signatures.json" file.
For more information on the bundle verification process see
https://www.openpolicyagent.org/docs/latest/management-bundles/#signature-verification.

The 'run' command can ONLY be used with the --bundle flag to verify signatures
for existing bundle files or directories following the bundle structure.

To skip bundle verification, use the --skip-verify flag.
`,
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()
			rt, err := initRuntime(ctx, cmdParams, args)
			lambdaPluginFactory := lambda.PluginFactory{}
			rt.Manager.Register(lambda.Name, lambdaPluginFactory.New(rt.Manager, nil))
			if err != nil {
				fmt.Println("error:", err)
				os.Exit(1)
			}
			startRuntime(ctx, rt, cmdParams.serverMode)
		},
	}

	addConfigFileFlag(runCommand.Flags(), &cmdParams.rt.ConfigFile)
	runCommand.Flags().BoolVarP(&cmdParams.serverMode, "server", "s", false, "start the runtime in server mode")
	runCommand.Flags().IntVar(&cmdParams.rt.ReadyTimeout, "ready-timeout", 0, "wait (in seconds) for configured plugins before starting server (value <= 0 disables ready check)")
	runCommand.Flags().StringVarP(&cmdParams.rt.HistoryPath, "history", "H", historyPath(), "set path of history file")
	cmdParams.rt.Addrs = runCommand.Flags().StringSliceP("addr", "a", []string{defaultAddr}, "set listening address of the server (e.g., [ip]:<port> for TCP, unix://<path> for UNIX domain socket)")
	cmdParams.rt.DiagnosticAddrs = runCommand.Flags().StringSlice("diagnostic-addr", []string{}, "set read-only diagnostic listening address of the server for /health and /metric APIs (e.g., [ip]:<port> for TCP, unix://<path> for UNIX domain socket)")
	runCommand.Flags().BoolVar(&cmdParams.rt.H2CEnabled, "h2c", false, "enable H2C for HTTP listeners")
	runCommand.Flags().StringVarP(&cmdParams.rt.OutputFormat, "format", "f", "pretty", "set shell output format, i.e, pretty, json")
	runCommand.Flags().BoolVarP(&cmdParams.rt.Watch, "watch", "w", false, "watch command line files for changes")
	addMaxErrorsFlag(runCommand.Flags(), &cmdParams.rt.ErrorLimit)
	runCommand.Flags().BoolVar(&cmdParams.rt.PprofEnabled, "pprof", false, "enables pprof endpoints")
	runCommand.Flags().StringVar(&cmdParams.tlsCertFile, "tls-cert-file", "", "set path of TLS certificate file")
	runCommand.Flags().StringVar(&cmdParams.tlsPrivateKeyFile, "tls-private-key-file", "", "set path of TLS private key file")
	runCommand.Flags().StringVar(&cmdParams.tlsCACertFile, "tls-ca-cert-file", "", "set path of TLS CA cert file")
	runCommand.Flags().DurationVar(&cmdParams.tlsCertRefresh, "tls-cert-refresh-period", 0, "set certificate refresh period")
	runCommand.Flags().Var(cmdParams.authentication, "authentication", "set authentication scheme")
	runCommand.Flags().Var(cmdParams.authorization, "authorization", "set authorization scheme")
	runCommand.Flags().Var(cmdParams.minTLSVersion, "min-tls-version", "set minimum TLS version to be used by OPA's server")
	runCommand.Flags().VarP(cmdParams.logLevel, "log-level", "l", "set log level")
	runCommand.Flags().Var(cmdParams.logFormat, "log-format", "set log format")
	runCommand.Flags().IntVar(&cmdParams.rt.GracefulShutdownPeriod, "shutdown-grace-period", 10, "set the time (in seconds) that the server will wait to gracefully shut down")
	runCommand.Flags().IntVar(&cmdParams.rt.ShutdownWaitPeriod, "shutdown-wait-period", 0, "set the time (in seconds) that the server will wait before initiating shutdown")
	addConfigOverrides(runCommand.Flags(), &cmdParams.rt.ConfigOverrides)
	addConfigOverrideFiles(runCommand.Flags(), &cmdParams.rt.ConfigOverrideFiles)
	addBundleModeFlag(runCommand.Flags(), &cmdParams.rt.BundleMode, false)
	runCommand.Flags().BoolVar(&cmdParams.skipVersionCheck, "skip-version-check", false, "disables anonymous version reporting (see: https://www.openpolicyagent.org/docs/latest/privacy)")
	addIgnoreFlag(runCommand.Flags(), &cmdParams.ignore)

	// bundle verification config
	addVerificationKeyFlag(runCommand.Flags(), &cmdParams.pubKey)
	addVerificationKeyIDFlag(runCommand.Flags(), &cmdParams.pubKeyID, defaultPublicKeyID)
	addSigningAlgFlag(runCommand.Flags(), &cmdParams.algorithm, defaultTokenSigningAlg)
	addBundleVerificationScopeFlag(runCommand.Flags(), &cmdParams.scope)
	addBundleVerificationSkipFlag(runCommand.Flags(), &cmdParams.skipBundleVerify, false)
	addBundleVerificationExcludeFilesFlag(runCommand.Flags(), &cmdParams.excludeVerifyFiles)

	usageTemplate := `Usage:
  {{.UseLine}} [files]

Flags:
{{.LocalFlags.FlagUsages | trimRightSpace}}
`

	runCommand.SetUsageTemplate(usageTemplate)

	RootCommand.AddCommand(runCommand)
}
