"""
AI-Driven Lab Requirements Analyzer.

Reads a repository's build files, CI configs, README, and Dockerfiles to determine
exactly what's needed to build and run the code for security testing.

This eliminates the friction of mismatched runtime versions (e.g., PHP 7 extension
on PHP 8 lab, Java 11 project on Java 21 lab, missing system libraries).
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional


# Files to read for understanding build requirements (priority order)
BUILD_FILES = [
    "Dockerfile",
    "docker-compose.yml", "docker-compose.yaml",
    ".github/workflows/ci.yml", ".github/workflows/test.yml", ".github/workflows/build.yml",
    ".travis.yml", ".circleci/config.yml", "Jenkinsfile",
    "Makefile", "CMakeLists.txt", "configure.ac", "config.m4",
    "requirements.txt", "setup.py", "pyproject.toml", "setup.cfg",
    "package.json", "package-lock.json",
    "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod", "go.sum",
    "Cargo.toml",
    "composer.json",
    "mix.exs",
    "pubspec.yaml",
    "build.sbt",
    "Package.swift",
    "build.zig",
    "README.md", "INSTALL.md", "CONTRIBUTING.md", "BUILD.md",
]


def gather_build_context(dest: Path, max_chars: int = 8000) -> str:
    """Read key build/config files from the repo to understand requirements.
    
    Returns a structured text summary of all build-relevant files found.
    """
    context_parts = []
    chars_used = 0
    
    for filename in BUILD_FILES:
        filepath = dest / filename
        if not filepath.exists():
            continue
        try:
            content = filepath.read_text(errors="ignore")
            # Truncate large files but keep enough for AI to understand
            if len(content) > 2000:
                content = content[:2000] + "\n... [truncated]"
            header = f"=== {filename} ===\n"
            if chars_used + len(header) + len(content) > max_chars:
                break
            context_parts.append(header + content)
            chars_used += len(header) + len(content)
        except Exception:
            continue

    for pattern in ("*.csproj", "*.sln", "*.gemspec"):
        if chars_used >= max_chars:
            break
        for filepath in list(dest.glob(pattern))[:3]:
            try:
                content = filepath.read_text(errors="ignore")
                if len(content) > 1500:
                    content = content[:1500] + "\n... [truncated]"
                header = f"=== {filepath.name} ===\n"
                if chars_used + len(header) + len(content) > max_chars:
                    break
                context_parts.append(header + content)
                chars_used += len(header) + len(content)
            except Exception:
                continue

    return "\n\n".join(context_parts)


def build_lab_analysis_prompt(dest: Path, language: str, port: int) -> str:
    """Build the AI prompt for lab requirements analysis."""
    context = gather_build_context(dest)
    
    return (
        f"You are analyzing a {language} repository to determine how to build and run it "
        f"for security testing in a Docker container.\n\n"
        f"The container already has: Ubuntu 26.04, Python 3.14, Ruby 3.x, Node 20.x, "
        f"Go 1.22+, OpenJDK 21, PHP 8.5, GCC, Make, curl, git, strace, gdb.\n\n"
        f"Analyze the build files below and generate a Dockerfile RUN block that:\n"
        f"1. Installs any MISSING system packages (apt-get) needed\n"
        f"2. Installs language-specific dependencies\n"
        f"3. Builds/compiles the project if needed\n"
        f"4. Makes the project testable (importable, executable, or serving HTTP)\n\n"
        f"CRITICAL RULES:\n"
        f"- If a specific language VERSION is needed (e.g., PHP 7.4 for a PHP 7 extension), "
        f"install that version via apt or from source\n"
        f"- Do NOT use '|| true' on install/build steps — a failed install must fail the image build\n"
        f"- The final CMD must be: python3 -m http.server {port} --directory /app\n"
        f"- Working directory is /app (repo source is already copied there)\n"
        f"- Keep it under 15 RUN lines\n\n"
        f"Respond with ONLY the Dockerfile content (RUN lines + CMD), no explanation:\n\n"
        f"--- Repository build files ---\n{context}\n"
    )


def parse_dockerfile_from_ai(ai_response: str, port: int) -> str:
    """Extract Dockerfile RUN/CMD lines from AI response."""
    lines = []
    for line in (ai_response or "").splitlines():
        stripped = line.strip()
        if stripped.startswith(("RUN ", "ENV ", "EXPOSE ", "CMD ", "WORKDIR ")):
            lines.append(stripped)
        elif stripped.startswith("#") and lines:  # keep comments if after first RUN
            lines.append(stripped)
    
    # Ensure CMD exists
    has_cmd = any(l.startswith("CMD ") for l in lines)
    if not has_cmd:
        lines.append(f"CMD python3 -m http.server {port} --directory /app")
    
    # Ensure EXPOSE exists
    has_expose = any(l.startswith("EXPOSE ") for l in lines)
    if not has_expose:
        lines.append(f"EXPOSE {port}")
    
    return "\n".join(lines) + "\n"


def generate_fallback_dockerfile(language: str, port: int) -> str:
    """Generate a basic fallback Dockerfile if AI analysis fails."""
    install = ""
    if language == "python":
        install = (
            "RUN pip3 install --no-cache-dir -r requirements.txt 2>/dev/null || true\n"
            "RUN pip3 install --no-cache-dir -e . 2>/dev/null || true\n"
        )
    elif language == "ruby/rails":
        install = (
            "RUN gem install bundler 2>/dev/null || true\n"
            "RUN bundle install 2>/dev/null || true\n"
        )
    elif language == "node":
        install = "RUN npm install 2>/dev/null || true\n"
    elif language == "java":
        install = "RUN mvn -q package -DskipTests 2>/dev/null || gradle build -x test 2>/dev/null || true\n"
    elif language == "c/cpp":
        install = "RUN make 2>/dev/null || cmake . && make 2>/dev/null || true\n"
    elif language == "go":
        install = "RUN go build ./... 2>/dev/null || true\n"
    elif language == "php":
        install = "RUN composer install --no-interaction 2>/dev/null || true\n"
    elif language == "rust":
        install = "RUN cargo build --release 2>/dev/null || true\n"
    elif language == "elixir":
        install = "RUN mix deps.get && mix compile 2>/dev/null || true\n"
    elif language in ("csharp", "dotnet"):
        install = "RUN dotnet restore && dotnet build 2>/dev/null || true\n"
    elif language == "scala":
        install = "RUN sbt -batch compile 2>/dev/null || true\n"
    elif language == "kotlin":
        install = "RUN gradle build -x test 2>/dev/null || true\n"
    
    return f"{install}EXPOSE {port}\nCMD python3 -m http.server {port} --directory /app\n"
