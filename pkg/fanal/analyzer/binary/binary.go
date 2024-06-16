package binary

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"golang.org/x/exp/maps"
)

const version = 1

var (
	binaries = binaryTypes{
		"nginx": {
			// versionRegexStr: `(?m)(\x00|\?)nginx version: [^\/]+\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:\+\d+)?(?:-\d+)?)`,
			versionRegexStr: `nginx version: [^\/]+\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:\+\d+)?(?:-\d+)?)`,
			license:         "GPL-3.0",
		},
	}
	versionRegexStr = `[0-9]+\.[0-9]+\.[0-9]`
)

type binaryType struct {
	versionRegexStr string
	license         string
}

type binaryTypes map[string]binaryType

func (b binaryTypes) keys() []string {
	return maps.Keys(b)
}

func init() {
	analyzer.RegisterAnalyzer(newBinaryAnalyzer())
}

// binaryAnalyzer is an analyzer for binary
type binaryAnalyzer struct{}

func newBinaryAnalyzer() *binaryAnalyzer {
	return &binaryAnalyzer{}
}

func (a *binaryAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	ctx = log.WithContextPrefix(ctx, "binary")
	log.InfoContext(ctx, "Binary scanning", log.String("file_path", input.FilePath))
	binaryName := filepath.Base(input.FilePath)
	binary, ok := binaries[binaryName]
	if !ok {
		log.ErrorContext(ctx, "not in binary", log.String("file_path", input.FilePath))
		return nil, errors.New("unsupported binary")
	}

	file, err := os.Open(filepath.Join(input.Dir, input.FilePath))
	if err != nil {
		log.ErrorContext(ctx, "open file", log.String("file_path", filepath.Join(input.Dir, input.FilePath)), log.Any("error", err))
		return nil, err
	}
	defer file.Close()

	var pkgs []types.Package
	reader := bufio.NewReader(file)
	for {
		text, _, err := reader.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			log.ErrorContext(ctx, "something happen", log.String("file_path", input.FilePath), log.Any("error", err))
			return nil, err
		}
		log.Info("Binary scanning", log.String("file_path", input.FilePath), log.String("regexstr", binary.versionRegexStr))
		binaryVersion := regexp.MustCompile(versionRegexStr).FindString(
			regexp.MustCompile(binary.versionRegexStr).FindString(string(text)),
		)
		if binaryVersion != "" {
			pkgs = append(pkgs, types.Package{
				Name:       filepath.Base(input.FilePath),
				Version:    binaryVersion,
				SrcName:    binaryName,
				SrcVersion: binaryVersion,
			})
			break
		}
	}
	for _, pkg := range pkgs {
		if pkg.Name != "" && pkg.Version != "" {
			pkg.ID = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
		}
	}

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: pkgs,
			},
		},
	}, nil
}

func (a *binaryAnalyzer) Required(filePath string, f os.FileInfo) bool {
	log.Info("Binary required", log.String("file_path", filePath))
	if f.IsDir() {
		return false
	}
	for _, b := range binaries.keys() {
		if filepath.Base(filePath) == b {
			return true
		}
	}
	return false
}

func (a *binaryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeBinary
}

func (a *binaryAnalyzer) Version() int {
	return version
}
