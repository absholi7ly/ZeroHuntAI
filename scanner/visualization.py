import os
import json
import datetime
import re
from collections import defaultdict

from utils.logger import get_logger

logger = get_logger()

class CallGraphVisualizer:
    """
    Visualizer for generating call graphs of codebases.
    """
    
    def __init__(self, code_base_dir, output_dir):

        self.code_base_dir = code_base_dir
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Mapping to track dangerous functions
        self.dangerous_functions = {
            'eval': {'type': 'Command Execution', 'risk': 'high'},
            'exec': {'type': 'Command Execution', 'risk': 'high'},
            'system': {'type': 'Command Execution', 'risk': 'high'},
            'os.popen': {'type': 'Command Execution', 'risk': 'high'},
            'os.system': {'type': 'Command Execution', 'risk': 'high'},
            'subprocess.call': {'type': 'Command Execution', 'risk': 'high'},
            'subprocess.Popen': {'type': 'Command Execution', 'risk': 'high'},
            'input': {'type': 'User Input', 'risk': 'medium'},
            'pickle.loads': {'type': 'Deserialization', 'risk': 'high'},
            'execute': {'type': 'SQL Execution', 'risk': 'high'},
            'query': {'type': 'SQL Execution', 'risk': 'high'},
            'innerHTML': {'type': 'XSS', 'risk': 'high'},
            'document.write': {'type': 'XSS', 'risk': 'high'},
            'mysql_query': {'type': 'SQL Execution', 'risk': 'high'}
        }
        
        logger.info(f"Initialized call graph visualizer for {code_base_dir}")
    
    def generate_graph(self, scan_result):

        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            graph_filename = f"call_graph_{timestamp}.html"
            graph_path = os.path.join(self.output_dir, graph_filename)
            
            # Build a graph structure of function calls
            graph_data = self._build_call_graph(scan_result)
            
            # Create the visualization HTML
            html_content = self._generate_visualization_html(graph_data, scan_result)
            
            # Write to file
            with open(graph_path, 'w') as f:
                f.write(html_content)
            
            logger.info(f"Generated call graph visualization: {graph_path}")
            return graph_path
            
        except Exception as e:
            logger.error(f"Error generating call graph: {str(e)}")
            return None
    
    def _build_call_graph(self, scan_result):

        graph = {
            'nodes': [],
            'links': [],
            'vulnerabilities': []
        }
        
        # Map of file paths to node IDs
        file_nodes = {}
        
        # Add nodes for each file with vulnerabilities
        node_id = 0
        for vuln in scan_result['vulnerabilities']:
            file_path = vuln['file']
            
            # Add node for the file if not already added
            if file_path not in file_nodes:
                file_nodes[file_path] = node_id
                graph['nodes'].append({
                    'id': node_id,
                    'name': os.path.basename(file_path),
                    'type': 'file',
                    'path': file_path,
                    'hasVulnerability': True
                })
                node_id += 1
            
            # Add a node for each vulnerable function/code snippet
            function_name = self._extract_function_name(vuln['code'])
            if function_name:
                function_node_id = node_id
                graph['nodes'].append({
                    'id': function_node_id,
                    'name': function_name,
                    'type': 'function',
                    'path': file_path,
                    'hasVulnerability': True,
                    'vulnerabilityType': vuln['type'],
                    'severity': vuln['severity']
                })
                
                # Add link from file to function
                graph['links'].append({
                    'source': file_nodes[file_path],
                    'target': function_node_id,
                    'type': 'contains',
                    'isVulnerable': True,
                    'severity': vuln['severity']
                })
                
                # Store vulnerability information
                graph['vulnerabilities'].append({
                    'nodeId': function_node_id,
                    'type': vuln['type'],
                    'severity': vuln['severity'],
                    'description': vuln['description'],
                    'line': vuln['line'],
                    'code': vuln['code']
                })
                
                node_id += 1
        
        return graph
    
    def _extract_function_name(self, code_snippet):

        # Try to extract function name with regex
        python_func_match = re.search(r'def\s+([a-zA-Z0-9_]+)\s*\(', code_snippet)
        js_func_match = re.search(r'function\s+([a-zA-Z0-9_]+)\s*\(', code_snippet)
        js_arrow_func_match = re.search(r'(const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*\(', code_snippet)
        
        if python_func_match:
            return python_func_match.group(1)
        elif js_func_match:
            return js_func_match.group(1)
        elif js_arrow_func_match:
            return js_arrow_func_match.group(2)
        
        # If no function name found, check for dangerous function calls
        for func_name in self.dangerous_functions:
            if func_name in code_snippet:
                return f"[Dangerous Call: {func_name}]"
        
        # Return a generic name if nothing specific found
        return "CodeSnippet"
    
    def _generate_visualization_html(self, graph_data, scan_result):

        # Get the current script directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        template_dir = os.path.join(os.path.dirname(current_dir), 'templates')
        template_path = os.path.join(template_dir, 'call_graph_template.html')
        
        # Ensure the template directory exists
        os.makedirs(template_dir, exist_ok=True)
        
        # Create template if it doesn't exist
        if not os.path.exists(template_path):
            self._create_call_graph_template(template_path)
        
        # Read the template
        with open(template_path, 'r') as f:
            template = f.read()
        
        # Replace placeholders
        html_content = template.replace('{{TIMESTAMP}}', scan_result['timestamp'])
        html_content = html_content.replace('{{TARGET}}', scan_result['target'])
        html_content = html_content.replace('{{GRAPH_DATA}}', json.dumps(graph_data))
        
        # Add vulnerability count details
        html_content = html_content.replace('{{TOTAL_VULNERABILITIES}}', str(scan_result['stats']['total_vulnerabilities']))
        html_content = html_content.replace('{{HIGH_SEVERITY}}', str(scan_result['stats']['high_severity']))
        html_content = html_content.replace('{{MEDIUM_SEVERITY}}', str(scan_result['stats']['medium_severity']))
        html_content = html_content.replace('{{LOW_SEVERITY}}', str(scan_result['stats']['low_severity']))
        
        return html_content
    
    def _create_call_graph_template(self, template_path):

        template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroHuntAI - Call Graph Visualization</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- D3.js for visualization -->
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
        }
        .container-fluid {
            padding: 20px;
        }
        #graph-container {
            width: 100%;
            height: 600px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
            background-color: #f9f9f9;
        }
        .node {
            cursor: pointer;
        }
        .node text {
            font-size: 12px;
            fill: #333;
        }
        .link {
            stroke-opacity: 0.6;
        }
        .header {
            background-color: #343a40;
            color: white;
            padding: 1rem 0;
            margin-bottom: 1rem;
        }
        .stats-card {
            text-align: center;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
        }
        .high-card {
            background-color: rgba(220, 53, 69, 0.1);
            border: 1px solid rgba(220, 53, 69, 0.2);
        }
        .medium-card {
            background-color: rgba(253, 126, 20, 0.1);
            border: 1px solid rgba(253, 126, 20, 0.2);
        }
        .low-card {
            background-color: rgba(13, 202, 240, 0.1);
            border: 1px solid rgba(13, 202, 240, 0.2);
        }
        .severity-high {
            color: #dc3545;
        }
        .severity-medium {
            color: #fd7e14;
        }
        .severity-low {
            color: #0dcaf0;
        }
        #details-panel {
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
            border: 1px solid #ddd;
            max-height: 600px;
            overflow-y: auto;
        }
        #node-details {
            margin-top: 15px;
        }
        .code-block {
            background-color: #f0f0f0;
            border-radius: 4px;
            padding: 10px;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
        }
        .tooltip {
            position: absolute;
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
            pointer-events: none;
            max-width: 300px;
            z-index: 1000;
        }
        .button-group {
            margin-bottom: 15px;
        }
        /* Legend styles */
        .legend {
            margin-top: 20px;
        }
        .legend-item {
            display: inline-block;
            margin-right: 20px;
        }
        .legend-color {
            display: inline-block;
            width: 20px;
            height: 20px;
            margin-right: 5px;
            vertical-align: middle;
            border-radius: 2px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <div class="row">
                <div class="col-md-8">
                    <h1><span style="color: #dc3545;">Zero</span><span style="color: white;">Hunt</span><span style="color: #0d6efd;">AI</span></h1>
                    <h3>Call Graph & Taint Flow Visualization</h3>
                </div>
                <div class="col-md-4 text-end">
                    <p class="mb-0"><strong>Scan Date:</strong> {{TIMESTAMP}}</p>
                    <p class="mb-0"><strong>Target:</strong> {{TARGET}}</p>
                </div>
            </div>
        </div>
    </div>
    
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-3">
                <div class="card mb-3">
                    <div class="card-header bg-dark text-white">
                        <h5 class="mb-0">Vulnerabilities</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-12 mb-2">
                                <div class="stats-card">
                                    <h3>{{TOTAL_VULNERABILITIES}}</h3>
                                    <p class="mb-0">Total</p>
                                </div>
                            </div>
                            <div class="col-12 mb-2">
                                <div class="stats-card high-card">
                                    <h3 class="severity-high">{{HIGH_SEVERITY}}</h3>
                                    <p class="mb-0">High</p>
                                </div>
                            </div>
                            <div class="col-12 mb-2">
                                <div class="stats-card medium-card">
                                    <h3 class="severity-medium">{{MEDIUM_SEVERITY}}</h3>
                                    <p class="mb-0">Medium</p>
                                </div>
                            </div>
                            <div class="col-12 mb-2">
                                <div class="stats-card low-card">
                                    <h3 class="severity-low">{{LOW_SEVERITY}}</h3>
                                    <p class="mb-0">Low</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header bg-dark text-white">
                        <h5 class="mb-0">Details</h5>
                    </div>
                    <div class="card-body" id="details-panel">
                        <p>Click on nodes to see details about code and dependencies.</p>
                        <div id="node-details">
                            <p>No node selected.</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-9">
                <div class="card">
                    <div class="card-header bg-dark text-white">
                        <div class="d-flex justify-content-between align-items-center">
                            <h5 class="mb-0">Call Graph & Data Flow</h5>
                            <div class="button-group">
                                <button id="reset-zoom" class="btn btn-sm btn-outline-light">Reset View</button>
                                <button id="toggle-physics" class="btn btn-sm btn-outline-light">Toggle Physics</button>
                            </div>
                        </div>
                    </div>
                    <div class="card-body p-0">
                        <div id="graph-container"></div>
                        
                        <!-- Legend -->
                        <div class="legend px-3 py-2">
                            <div class="legend-item">
                                <div class="legend-color" style="background-color: #6c757d;"></div>
                                <span>File Node</span>
                            </div>
                            <div class="legend-item">
                                <div class="legend-color" style="background-color: #0d6efd;"></div>
                                <span>Function Node</span>
                            </div>
                            <div class="legend-item">
                                <div class="legend-color" style="background-color: #dc3545;"></div>
                                <span>Vulnerable Function</span>
                            </div>
                            <div class="legend-item">
                                <div class="legend-color" style="background-color: #198754;"></div>
                                <span>Safe Data Flow</span>
                            </div>
                            <div class="legend-item">
                                <div class="legend-color" style="background-color: #dc3545;"></div>
                                <span>Risky Data Flow</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Graph data from the backend
        const graphData = {{GRAPH_DATA}};
        
        // D3.js visualization
        document.addEventListener('DOMContentLoaded', function() {
            const width = document.getElementById('graph-container').clientWidth;
            const height = document.getElementById('graph-container').clientHeight;
            
            // Create tooltip
            const tooltip = d3.select('body').append('div')
                .attr('class', 'tooltip')
                .style('opacity', 0);
            
            // Create SVG element
            const svg = d3.select('#graph-container')
                .append('svg')
                .attr('width', width)
                .attr('height', height)
                .call(d3.zoom().on('zoom', (event) => {
                    g.attr('transform', event.transform);
                }));
            
            const g = svg.append('g');
            
            // Create the links
            const link = g.selectAll('.link')
                .data(graphData.links)
                .enter().append('line')
                .attr('class', 'link')
                .attr('stroke-width', d => d.isVulnerable ? 3 : 1)
                .attr('stroke', d => {
                    if (d.isVulnerable) {
                        if (d.severity === 'High') return '#dc3545';
                        if (d.severity === 'Medium') return '#fd7e14';
                        if (d.severity === 'Low') return '#0dcaf0';
                    }
                    return '#999';
                });
            
            // Create the nodes
            const node = g.selectAll('.node')
                .data(graphData.nodes)
                .enter().append('g')
                .attr('class', 'node')
                .on('click', function(event, d) {
                    showNodeDetails(d);
                })
                .on('mouseover', function(event, d) {
                    tooltip.transition()
                        .duration(200)
                        .style('opacity', .9);
                    tooltip.html(`<strong>${d.name}</strong><br/>${d.type}`)
                        .style('left', (event.pageX + 10) + 'px')
                        .style('top', (event.pageY - 28) + 'px');
                })
                .on('mouseout', function() {
                    tooltip.transition()
                        .duration(500)
                        .style('opacity', 0);
                })
                .call(d3.drag()
                    .on('start', dragStarted)
                    .on('drag', dragged)
                    .on('end', dragEnded));
            
            // Add circles to the nodes
            node.append('circle')
                .attr('r', d => d.type === 'file' ? 12 : 8)
                .attr('fill', d => {
                    if (d.type === 'file') return '#6c757d';
                    if (d.hasVulnerability) {
                        if (d.severity === 'High') return '#dc3545';
                        if (d.severity === 'Medium') return '#fd7e14';
                        if (d.severity === 'Low') return '#0dcaf0';
                    }
                    return '#0d6efd';
                });
            
            // Add labels to the nodes
            node.append('text')
                .attr('dx', 15)
                .attr('dy', 5)
                .text(d => d.name)
                .attr('fill', d => d.hasVulnerability ? '#dc3545' : '#333');
            
            // Add physics simulation
            const simulation = d3.forceSimulation(graphData.nodes)
                .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-500))
                .force('center', d3.forceCenter(width / 2, height / 2))
                .force('collision', d3.forceCollide().radius(30))
                .on('tick', ticked);
            
            let physicsEnabled = true;
            
            // Toggle physics button
            document.getElementById('toggle-physics').addEventListener('click', function() {
                if (physicsEnabled) {
                    simulation.stop();
                    physicsEnabled = false;
                    this.textContent = 'Enable Physics';
                } else {
                    simulation.restart();
                    physicsEnabled = true;
                    this.textContent = 'Disable Physics';
                }
            });
            
            // Reset zoom button
            document.getElementById('reset-zoom').addEventListener('click', function() {
                svg.transition().duration(750).call(
                    d3.zoom().transform,
                    d3.zoomIdentity,
                    d3.zoomTransform(svg.node()).invert([width / 2, height / 2])
                );
            });
            
            function ticked() {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);
                
                node
                    .attr('transform', d => `translate(${d.x},${d.y})`);
            }
            
            function dragStarted(event, d) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }
            
            function dragged(event, d) {
                d.fx = event.x;
                d.fy = event.y;
            }
            
            function dragEnded(event, d) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }
            
            function showNodeDetails(node) {
                let detailsHtml = `<h5>${node.name}</h5>`;
                detailsHtml += `<p><strong>Type:</strong> ${node.type}</p>`;
                
                if (node.path) {
                    detailsHtml += `<p><strong>Path:</strong> ${node.path}</p>`;
                }
                
                if (node.hasVulnerability) {
                    detailsHtml += `<p><strong>Has Vulnerability:</strong> Yes</p>`;
                    
                    // Find vulnerability details for this node
                    const nodeVulns = graphData.vulnerabilities.filter(v => v.nodeId === node.id);
                    if (nodeVulns.length > 0) {
                        nodeVulns.forEach(v => {
                            let severityClass = '';
                            if (v.severity === 'High') severityClass = 'severity-high';
                            else if (v.severity === 'Medium') severityClass = 'severity-medium';
                            else if (v.severity === 'Low') severityClass = 'severity-low';
                            
                            detailsHtml += `
                                <div class="card mt-2 mb-2">
                                    <div class="card-header">
                                        <strong class="${severityClass}">${v.severity} Severity:</strong> ${v.type}
                                    </div>
                                    <div class="card-body">
                                        <p>${v.description}</p>
                                        <p><strong>Line:</strong> ${v.line}</p>
                                        <div class="code-block">${escapeHtml(v.code)}</div>
                                    </div>
                                </div>
                            `;
                        });
                    }
                }
                
                document.getElementById('node-details').innerHTML = detailsHtml;
            }
            
            // Helper function to escape HTML
            function escapeHtml(text) {
                return text
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#039;");
            }
        });
    </script>

    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""
        # Create the template file
        with open(template_path, 'w') as f:
            f.write(template)
        
        logger.info(f"Created call graph template at: {template_path}")
