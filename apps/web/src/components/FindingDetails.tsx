"use client";

import React from "react";
import { AlertTriangle, AlertOctagon, Info, ShieldAlert } from "lucide-react";
import { Finding } from "../types";

interface FindingDetailsProps {
  findings: Finding[];
}

export default function FindingDetails({ findings }: FindingDetailsProps) {
  const severityBadge = (sev: string) => {
    switch (sev) {
      case "ERROR":
        return (
          <span className="flex items-center gap-1 bg-red-950/70 border border-red-700/60 text-red-400 text-xs px-2.5 py-0.5 rounded font-bold">
            <AlertOctagon className="w-3.5 h-3.5" /> ERROR
          </span>
        );
      case "WARNING":
        return (
          <span className="flex items-center gap-1 bg-amber-950/70 border border-amber-700/60 text-amber-400 text-xs px-2.5 py-0.5 rounded font-bold">
            <AlertTriangle className="w-3.5 h-3.5" /> WARNING
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1 bg-sky-950/70 border border-sky-700/60 text-sky-400 text-xs px-2.5 py-0.5 rounded font-bold">
            <Info className="w-3.5 h-3.5" /> INFO
          </span>
        );
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-sky-400" />
          04. Deterministic Finding Inspector
        </h2>
        <p className="text-sm text-slate-400">
          Rule-level outputs from R100–R799 checking structural validity, timestamps, prerequisites, and contradictions.
        </p>
      </div>

      <div className="space-y-4">
        {findings.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-500">
            No validation findings generated. Run an analysis in the Workspace first.
          </div>
        ) : (
          findings.map((f) => (
            <div
              key={f.id}
              className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3 hover:border-slate-700 transition-colors"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <span className="font-mono font-bold text-slate-200 bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-sm">
                    {f.rule_id}
                  </span>
                  <h3 className="font-bold text-slate-100 text-sm">{f.rule_name}</h3>
                </div>
                <div>{severityBadge(f.severity)}</div>
              </div>

              <p className="text-sm text-slate-300 leading-relaxed">{f.explanation}</p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-slate-950/80 p-3 rounded-lg border border-slate-800/60">
                <div>
                  <span className="text-slate-500 block uppercase font-semibold">Affected Nodes:</span>
                  <span className="text-sky-300 font-mono">
                    {f.affected_node_ids && f.affected_node_ids.length > 0
                      ? f.affected_node_ids.join(", ")
                      : "Graph-wide invariant"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block uppercase font-semibold">Evidence References:</span>
                  <span className="text-emerald-400 font-mono">
                    {f.evidence_refs && f.evidence_refs.length > 0 ? f.evidence_refs.join(", ") : "None (Rule inference)"}
                  </span>
                </div>
              </div>

              {f.remediation_guidance && (
                <div className="text-xs text-slate-400 bg-slate-800/40 border-l-2 border-sky-400 pl-3 py-1.5">
                  <strong className="text-slate-300">Remediation Guidance:</strong> {f.remediation_guidance}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
