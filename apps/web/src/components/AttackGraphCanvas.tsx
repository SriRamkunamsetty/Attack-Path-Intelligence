"use client";

import React, { useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { AttackGraphExport, GraphNode, GraphEdge } from "../types";

interface AttackGraphCanvasProps {
  graph: AttackGraphExport | null;
}

const nodeTypeColors: Record<string, string> = {
  observation: "#38bdf8", // Sky blue
  attack_step: "#f97316", // Orange
  asset: "#10b981",       // Emerald green
  technique: "#8b5cf6",   // Purple
  security_control: "#06b6d4", // Cyan
  finding: "#ef4444",     // Red
};

export default function AttackGraphCanvas({ graph }: AttackGraphCanvasProps) {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const initialNodes: Node[] = useMemo(() => {
    if (!graph || !graph.nodes) return [];

    return graph.nodes.map((n, index) => {
      const angle = (index / graph.nodes.length) * 2 * Math.PI;
      const x = 400 + Math.cos(angle) * 280;
      const y = 300 + Math.sin(angle) * 200;
      const color = nodeTypeColors[n.type] || "#94a3b8";

      return {
        id: n.id,
        position: { x, y },
        data: {
          label: (
            <div className="text-left font-sans">
              <div className="text-[10px] uppercase font-bold tracking-wider opacity-75">{n.type}</div>
              <div className="font-semibold text-xs leading-tight truncate max-w-[140px]">{n.label || n.id}</div>
            </div>
          ),
          rawNode: n,
        },
        style: {
          background: "#0f172a",
          color: "#f8fafc",
          border: `2px solid ${color}`,
          borderRadius: "8px",
          padding: "8px 12px",
          boxShadow: `0 0 12px ${color}33`,
        },
      };
    });
  }, [graph]);

  const initialEdges: Edge[] = useMemo(() => {
    if (!graph || !graph.edges) return [];

    return graph.edges.map((e) => {
      const isContra = e.edge_type === "CONTRADICTS";
      const isEnables = e.edge_type === "ENABLES";
      const stroke = isContra ? "#ef4444" : isEnables ? "#38bdf8" : "#64748b";

      return {
        id: e.id,
        source: e.source,
        target: e.target,
        animated: isEnables,
        style: {
          stroke,
          strokeWidth: isContra ? 2.5 : 2,
          strokeDasharray: isContra ? "5, 5" : undefined,
        },
        label: e.edge_type,
        labelStyle: { fill: stroke, fontSize: 10, fontWeight: 700 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: stroke,
        },
      };
    });
  }, [graph]);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-4 h-[calc(100vh-140px)] flex flex-col">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-slate-100">03. Directed Attack Graph</h2>
          <p className="text-sm text-slate-400">
            Interactive NetworkX-powered topology distinguishing facts, hypotheses, and contradictions.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg">
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-sky-400"></span> Observation</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-orange-400"></span> Attack Step</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span> Asset</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Contradiction</span>
        </div>
      </div>

      <div className="flex-1 bg-slate-950 border border-slate-800 rounded-xl relative overflow-hidden flex">
        <div className="flex-1 h-full">
          <ReactFlow
            nodes={initialNodes}
            edges={initialEdges}
            onNodeClick={(_, node) => setSelectedNode((node.data as any).rawNode)}
            fitView
          >
            <Background color="#334155" gap={20} size={1} />
            <Controls className="bg-slate-900 border-slate-800 text-slate-200 fill-slate-200" />
            <MiniMap
              nodeColor={(n) => nodeTypeColors[(n.data as any)?.rawNode?.type] || "#94a3b8"}
              className="bg-slate-900 border border-slate-800 rounded-lg"
            />
          </ReactFlow>
        </div>

        {selectedNode && (
          <div className="w-80 bg-slate-900 border-l border-slate-800 p-4 space-y-3 overflow-y-auto">
            <div className="flex justify-between items-center">
              <span className="text-xs uppercase font-bold text-sky-400">{selectedNode.type} Details</span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-xs text-slate-400 hover:text-slate-200"
              >
                Close
              </button>
            </div>
            <h3 className="font-bold text-slate-100 text-sm">{selectedNode.label}</h3>
            <div className="text-xs font-mono text-slate-400">ID: {selectedNode.id}</div>
            <pre className="text-[11px] font-mono bg-slate-950 border border-slate-800 p-2.5 rounded text-slate-300 overflow-x-auto">
              {JSON.stringify(selectedNode.data, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
