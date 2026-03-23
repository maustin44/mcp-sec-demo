#!/usr/bin/env python3
"""
Local MCP server for VS Code integration.

This server runs as a stdio MCP process inside VS Code (via .vscode/mcp.json).
It exposes tools that allow Claude in VS Code to:
  1. List running containers/services in the AWS environment
  2. Pull open findings from DefectDojo
  3. Fetch source code context for a given finding
  4. Submit a triage verdict back to DefectDojo
  5. Generate a security report from current findings

This is the local IDE-connected flow the client described:
  VS Code (Claude) -> MCP server (this file) -> AWS / DefectDojo APIs

Phase 3 implementation — currently returns stub responses.
"""

import sys
import json
import os
import logging

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
log = logging.getLogger('mcp_server')

# --- MCP protocol helpers ---

def send(msg: dict):
    """Write a JSON-RPC message to stdout."""
    sys.stdout.write(json.dumps(msg) + '\n')
    sys.stdout.flush()

def respond(id, result):
    send({'jsonrpc': '2.0', 'id': id, 'result': result})

def error(id, code, message):
    send({'jsonrpc': '2.0', 'id': id, 'error': {'code': code, 'message': message}})

# --- Tool definitions ---

TOOLS = [
    {
        'name': 'list_services',
        'description': 'List microservices and containers running in the AWS environment (ECS tasks, EC2 instances).',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'filter': {'type': 'string', 'description': 'Optional name filter'}
            }
        }
    },
    {
        'name': 'get_findings',
        'description': 'Retrieve open security findings from DefectDojo for a given service or all services.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'service': {'type': 'string', 'description': 'Service name to filter by (optional)'},
                'severity': {'type': 'string', 'enum': ['Critical', 'High', 'Medium', 'Low', 'Info']}
            }
        }
    },
    {
        'name': 'get_code_context',
        'description': 'Fetch the source code surrounding a specific finding for AI analysis.',
        'inputSchema': {
            'type': 'object',
            'required': ['file_path', 'line_number'],
            'properties': {
                'file_path': {'type': 'string'},
                'line_number': {'type': 'integer'},
                'context_lines': {'type': 'integer', 'default': 10}
            }
        }
    },
    {
        'name': 'triage_finding',
        'description': 'Submit a triage verdict for a finding back to DefectDojo.',
        'inputSchema': {
            'type': 'object',
            'required': ['finding_id', 'verdict'],
            'properties': {
                'finding_id': {'type': 'integer'},
                'verdict': {'type': 'string', 'enum': ['true_positive', 'false_positive', 'needs_review']},
                'notes': {'type': 'string', 'description': 'AI reasoning for the verdict'}
            }
        }
    },
    {
        'name': 'generate_report',
        'description': 'Generate a security report summarising all findings, verdicts, and recommendations.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'format': {'type': 'string', 'enum': ['markdown', 'json'], 'default': 'markdown'}
            }
        }
    }
]

# --- Tool handlers (Phase 3 stubs) ---

def handle_list_services(params):
    log.info('list_services called')
    return {
        'services': [
            {'name': 'mcp-sec-demo-spa', 'type': 'CloudFront+S3', 'status': 'running'},
            {'name': 'mcp-sec-demo-defectdojo', 'type': 'ECS Fargate', 'status': 'running'},
        ],
        'note': 'Phase 3: will query ECS DescribeTasks + EC2 DescribeInstances via boto3'
    }

def handle_get_findings(params):
    log.info('get_findings called')
    defectdojo_url = os.environ.get('DEFECTDOJO_URL', '')
    if not defectdojo_url:
        return {'findings': [], 'note': 'DEFECTDOJO_URL not set — DefectDojo not deployed yet'}
    return {
        'findings': [],
        'note': 'Phase 3: will call GET /api/v2/findings/ on DefectDojo'
    }

def handle_get_code_context(params):
    file_path = params.get('file_path', '')
    line_number = params.get('line_number', 1)
    context_lines = params.get('context_lines', 10)
    try:
        with open(file_path) as f:
            lines = f.readlines()
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        snippet = ''.join(lines[start:end])
        return {'file': file_path, 'line': line_number, 'snippet': snippet}
    except FileNotFoundError:
        return {'error': f'File not found: {file_path}'}

def handle_triage_finding(params):
    log.info(f'triage_finding called: {params}')
    return {
        'status': 'stub',
        'note': 'Phase 3: will PATCH /api/v2/findings/{id}/ on DefectDojo with verdict + notes'
    }

def handle_generate_report(params):
    fmt = params.get('format', 'markdown')
    return {
        'format': fmt,
        'note': 'Phase 3: will pull all findings + verdicts from DefectDojo and ask Claude to write a narrative report'
    }

DISPATCH = {
    'list_services':    handle_list_services,
    'get_findings':     handle_get_findings,
    'get_code_context': handle_get_code_context,
    'triage_finding':   handle_triage_finding,
    'generate_report':  handle_generate_report,
}

# --- MCP main loop ---

def main():
    log.info('MCP server starting (stdio transport)')
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get('method', '')
        msg_id = msg.get('id')
        params = msg.get('params', {})

        if method == 'initialize':
            respond(msg_id, {
                'protocolVersion': '2024-11-05',
                'serverInfo': {'name': 'mcp-sec-demo', 'version': '0.1.0'},
                'capabilities': {'tools': {}}
            })

        elif method == 'tools/list':
            respond(msg_id, {'tools': TOOLS})

        elif method == 'tools/call':
            tool_name = params.get('name')
            tool_params = params.get('arguments', {})
            handler = DISPATCH.get(tool_name)
            if handler:
                result = handler(tool_params)
                respond(msg_id, {
                    'content': [{'type': 'text', 'text': json.dumps(result, indent=2)}]
                })
            else:
                error(msg_id, -32601, f'Tool not found: {tool_name}')

        elif method == 'notifications/initialized':
            pass  # no response needed

        else:
            if msg_id is not None:
                error(msg_id, -32601, f'Method not found: {method}')

if __name__ == '__main__':
    main()
