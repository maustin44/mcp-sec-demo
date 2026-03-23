# VS Code MCP Setup Guide

This guide sets up the local MCP server so Claude in VS Code can connect to your AWS environment and DefectDojo to triage findings directly from your IDE — the flow the client described.

## Architecture

```
VS Code (Claude extension)
        |
        | stdio
        v
agents/mcp_server.py   <-- this file runs locally
        |
        |-- AWS APIs (boto3)     --> list ECS tasks, containers
        |-- DefectDojo REST API  --> get/update findings
        |-- local filesystem     --> get code context
```

## Prerequisites

1. **Install the Claude VS Code extension**
   - Open VS Code → Extensions → search `Claude` by Anthropic → Install

2. **Install Python dependencies**
   ```bash
   pip install anthropic requests boto3
   ```

3. **Set environment variables**

   Add these to your shell profile (`~/.bashrc`, `~/.zshrc`, or Windows environment variables):
   ```bash
   export ANTHROPIC_API_KEY=your-key-from-console.anthropic.com
   export AWS_ACCESS_KEY_ID=your-aws-key
   export AWS_SECRET_ACCESS_KEY=your-aws-secret
   export DEFECTDOJO_URL=http://your-defectdojo-alb-url
   export DEFECTDOJO_API_KEY=your-defectdojo-api-key
   ```

   On Windows (PowerShell):
   ```powershell
   $env:ANTHROPIC_API_KEY="your-key"
   $env:AWS_ACCESS_KEY_ID="your-aws-key"
   $env:AWS_SECRET_ACCESS_KEY="your-aws-secret"
   $env:DEFECTDOJO_URL="http://your-defectdojo-alb-url"
   $env:DEFECTDOJO_API_KEY="your-defectdojo-api-key"
   ```

## How it works

The `.vscode/mcp.json` file in the repo root tells VS Code to launch `agents/mcp_server.py` as a local stdio MCP process when Claude starts. Claude then has access to these tools:

| Tool | What it does |
|------|--------------|
| `list_services` | Lists ECS tasks and containers running in AWS |
| `get_findings` | Pulls open findings from DefectDojo |
| `get_code_context` | Fetches source code around a finding's file/line |
| `triage_finding` | Submits a verdict (true/false positive) back to DefectDojo |
| `generate_report` | Asks Claude to write a narrative security report |

## Usage

Once configured, open the Claude chat panel in VS Code and type:

```
List all open security findings and triage each one
```

or:

```
Generate a security report for this sprint
```

Claude will call the MCP tools automatically, pulling context from your live environment.

## Current status

- Phase 1-2: Tool stubs return placeholder data
- Phase 3: Full implementation — boto3 AWS queries + DefectDojo API calls wired in
