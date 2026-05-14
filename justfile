# Vulnerability Management Guide — development tasks
# Install just: https://github.com/casey/just

# Default: list available recipes
default:
    @just --list

# Start local dev server with live reload
dev:
    hugo server --disableFastRender --port 1313

# Build the site (minified)
build:
    hugo --minify

# Remove build output
clean:
    rm -rf public/ .hugo_build.lock

# Check for broken links in the built site
check-links: build
    @command -v htmltest >/dev/null 2>&1 || (echo "Install htmltest: go install github.com/wjdp/htmltest@latest" && exit 1)
    htmltest public/

# Create a new scanner guide stub — just new-scanner my-tool
new-scanner name:
    #!/usr/bin/env bash
    set -e
    mkdir -p content/scanners
    out="content/scanners/{{ name }}.md"
    python3 _scripts/new-guide.py scanner "{{ name }}" "$out"
    echo "Created $out"

# Create a new rules guide stub — just new-rule my-rule
new-rule name:
    #!/usr/bin/env bash
    set -e
    mkdir -p content/rules
    out="content/rules/{{ name }}.md"
    python3 _scripts/new-guide.py rule "{{ name }}" "$out"
    echo "Created $out"

# Validate Hugo config and templates
validate:
    hugo --templateMetrics --templateMetricsHints 2>&1 | head -40

# Show page count by section
stats: build
    @echo "Pages by section:"
    @find public -name "index.html" | sed 's|public/||;s|/index.html||' | sort | head -40
