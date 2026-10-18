"""Interactive standalone HTML report generator for AttackPath Intelligence."""

from __future__ import annotations

import json
from packages.schemas.models import AnalysisResult, PathStatus, Severity


class HTMLReportGenerator:
    """Generates a standalone, beautiful HTML report with interactive graph and evidence explorer."""

    @classmethod
    def generate(cls, result: AnalysisResult) -> str:
        res_json = result.model_dump_json(indent=2)
        metrics = result.metrics
        findings = result.findings
        paths = result.candidate_paths
        graph = result.graph

        nodes_json = json.dumps([n.model_dump(mode="json") for n in graph.nodes])
        edges_json = json.dumps([e.model_dump(mode="json") for e in graph.edges])

        severity_colors = {
            Severity.ERROR.value: "#ef4444",
            Severity.WARNING.value: "#f59e0b",
            Severity.INFO.value: "#3b82f6",
        }

        path_colors = {
            PathStatus.SUPPORTED.value: "#10b981",
            PathStatus.PARTIALLY_SUPPORTED.value: "#f59e0b",
            PathStatus.UNSUBSTANTIATED.value: "#6b7280",
            PathStatus.CONTRADICTED.value: "#ef4444",
        }

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AttackPath Intelligence Analysis Report - {result.scenario_id}</title>
  <style>
    :root {{
      --bg-primary: #0f172a;
      --bg-secondary: #1e293b;
      --bg-card: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-dark: #0284c7;
      --border: #475569;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg-primary);
      color: var(--text-main);
      line-height: 1.5;
      padding: 24px;
    }}
    header {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    h1 {{ font-size: 24px; color: var(--accent); }}
    .subtitle {{ color: var(--text-muted); font-size: 14px; margin-top: 4px; }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }}
    .grid-metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .card {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
    }}
    .card-title {{ font-size: 13px; text-transform: uppercase; color: var(--text-muted); }}
    .card-value {{ font-size: 28px; font-weight: 700; color: var(--accent); margin-top: 6px; }}
    .section-title {{ font-size: 18px; margin: 24px 0 12px 0; border-left: 4px solid var(--accent); padding-left: 10px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      background: var(--bg-secondary);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; }}
    th {{ background: var(--bg-card); color: var(--accent); font-weight: 600; }}
    tr:hover {{ background: rgba(56, 189, 248, 0.05); }}
    .canvas-container {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 12px;
      height: 480px;
      position: relative;
      overflow: hidden;
      margin-bottom: 24px;
    }}
    #graphCanvas {{ width: 100%; height: 100%; display: block; }}
    .canvas-legend {{
      position: absolute;
      top: 12px;
      right: 12px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 14px;
      font-size: 12px;
    }}
    .legend-item {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }}
    .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
    .tab-bar {{ display: flex; gap: 12px; margin-bottom: 16px; }}
    .tab-btn {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
    }}
    .tab-btn.active {{ background: var(--accent); color: #000; border-color: var(--accent); }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>AttackPath Intelligence Report</h1>
      <div class="subtitle">Scenario: <strong>{result.scenario_id}</strong> · Engine Version: {result.rule_engine_version} · Knowledge Base: {result.dataset_version}</div>
    </div>
    <div>
      <span class="badge" style="background: rgba(56, 189, 248, 0.2); color: var(--accent);">Analysis Complete</span>
    </div>
  </header>

  <div class="grid-metrics">
    <div class="card">
      <div class="card-title">Graph Nodes</div>
      <div class="card-value">{metrics.get("total_nodes", 0)}</div>
    </div>
    <div class="card">
      <div class="card-title">Directed Edges</div>
      <div class="card-value">{metrics.get("total_edges", 0)}</div>
    </div>
    <div class="card">
      <div class="card-title">Evidence Coverage</div>
      <div class="card-value">{int(metrics.get("evidence_coverage_ratio", 0) * 100)}%</div>
    </div>
    <div class="card">
      <div class="card-title">Validation Findings</div>
      <div class="card-value" style="color: {severity_colors['ERROR'] if metrics.get('findings_count', {}).get('error', 0) > 0 else 'var(--accent)'}">
        {metrics.get("findings_count", {}).get("total", 0)}
      </div>
    </div>
    <div class="card">
      <div class="card-title">Candidate Paths</div>
      <div class="card-value">{len(paths)}</div>
    </div>
  </div>

  <h2 class="section-title">Attack Graph Topology</h2>
  <div class="canvas-container">
    <canvas id="graphCanvas"></canvas>
    <div class="canvas-legend">
      <div class="legend-item"><span class="dot" style="background: #3b82f6;"></span> Observation</div>
      <div class="legend-item"><span class="dot" style="background: #f97316;"></span> Attack Step</div>
      <div class="legend-item"><span class="dot" style="background: #10b981;"></span> Asset</div>
      <div class="legend-item"><span class="dot" style="background: #8b5cf6;"></span> MITRE Technique</div>
      <div class="legend-item"><span class="dot" style="background: #ef4444;"></span> Contradiction / Finding</div>
    </div>
  </div>

  <h2 class="section-title">Candidate Attack Paths & Uncertainty Reasoning</h2>
  <table>
    <thead>
      <tr>
        <th>Path ID</th>
        <th>Status</th>
        <th>Path Steps</th>
        <th>Confidence & Evidence Rationale</th>
        <th>Missing / Discriminator Evidence</th>
      </tr>
    </thead>
    <tbody>
"""
        for p in paths:
            color = path_colors.get(p.status.value, "#94a3b8")
            missing_html = "<br>".join(p.missing_evidence) if p.missing_evidence else "None (Fully evidenced)"
            html += f"""
      <tr>
        <td><strong>{p.path_id}</strong></td>
        <td><span class="badge" style="background: {color}22; color: {color}; border: 1px solid {color};">{p.status.value}</span></td>
        <td>{' &rarr; '.join(p.step_ids)}</td>
        <td>{p.confidence_rationale}</td>
        <td style="color: var(--text-muted); font-size: 13px;">{missing_html}</td>
      </tr>
"""
        html += """
    </tbody>
  </table>

  <h2 class="section-title">Deterministic Rule Validation Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Rule ID</th>
        <th>Severity</th>
        <th>Affected Nodes</th>
        <th>Explanation</th>
        <th>Remediation Guidance</th>
      </tr>
    </thead>
    <tbody>
"""
        for f in findings:
            sev_color = severity_colors.get(f.severity.value, "#94a3b8")
            html += f"""
      <tr>
        <td><code>{f.rule_id}</code></td>
        <td><span class="badge" style="background: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color};">{f.severity.value}</span></td>
        <td>{', '.join(f.affected_node_ids) if f.affected_node_ids else 'Graph-wide'}</td>
        <td>{f.explanation}</td>
        <td style="color: var(--text-muted); font-size: 13px;">{f.remediation_guidance}</td>
      </tr>
"""
        html += f"""
    </tbody>
  </table>

  <script>
    const rawNodes = {nodes_json};
    const rawEdges = {edges_json};

    const canvas = document.getElementById('graphCanvas');
    const ctx = canvas.getContext('2d');

    function resize() {{
      canvas.width = canvas.parentElement.clientWidth;
      canvas.height = canvas.parentElement.clientHeight;
      draw();
    }}
    window.addEventListener('resize', resize);

    const typeColors = {{
      'observation': '#3b82f6',
      'attack_step': '#f97316',
      'asset': '#10b981',
      'technique': '#8b5cf6',
      'security_control': '#06b6d4',
      'finding': '#ef4444'
    }};

    // Position nodes horizontally by type or index
    const nodeCoords = {{}};
    const stepX = Math.max(120, (window.innerWidth - 100) / (rawNodes.length + 1));

    rawNodes.forEach((node, i) => {{
      const angle = (i / rawNodes.length) * 2 * Math.PI;
      const rx = (canvas.width || 800) / 2 + Math.cos(angle) * 180;
      const ry = (canvas.height || 480) / 2 + Math.sin(angle) * 140;
      nodeCoords[node.id] = {{ x: rx, y: ry, node }};
    }});

    function draw() {{
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Draw edges
      ctx.lineWidth = 1.5;
      rawEdges.forEach(e => {{
        const u = nodeCoords[e.source];
        const v = nodeCoords[e.target];
        if (u && v) {{
          ctx.beginPath();
          ctx.moveTo(u.x, u.y);
          ctx.lineTo(v.x, v.y);
          ctx.strokeStyle = e.edge_type === 'CONTRADICTS' ? '#ef4444' : (e.edge_type === 'ENABLES' ? '#38bdf8' : '#475569');
          if (e.edge_type === 'CONTRADICTS') ctx.setLineDash([5, 5]);
          else ctx.setLineDash([]);
          ctx.stroke();

          // Arrow head
          const angle = Math.atan2(v.y - u.y, v.x - u.x);
          ctx.beginPath();
          ctx.moveTo(v.x, v.y);
          ctx.lineTo(v.x - 12 * Math.cos(angle - Math.PI / 6), v.y - 12 * Math.sin(angle - Math.PI / 6));
          ctx.lineTo(v.x - 12 * Math.cos(angle + Math.PI / 6), v.y - 12 * Math.sin(angle + Math.PI / 6));
          ctx.fillStyle = ctx.strokeStyle;
          ctx.fill();
        }}
      }});

      // Draw nodes
      Object.values(nodeCoords).forEach(item => {{
        const color = typeColors[item.node.type] || '#94a3b8';
        ctx.beginPath();
        ctx.arc(item.x, item.y, 14, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.strokeStyle = '#fff';
        ctx.stroke();

        ctx.fillStyle = '#f8fafc';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(item.node.id, item.x, item.y + 26);
      }});
    }}

    setTimeout(resize, 100);
  </script>
</body>
</html>
"""
        return html
