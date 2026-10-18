"use client";

import React from "react";
import { Download, FileJson, FileText, CheckCircle2, TrendingUp } from "lucide-react";
import { AnalysisResult } from "../types";

interface ReportEvaluationProps {
  result: AnalysisResult | null;
}

export default function ReportEvaluation({ result }: ReportEvaluationProps) {
  if (!result) {
    return (
      <div className="p-6 max-w-7xl mx-auto text-center text-slate-500 py-16">
        No analysis data available to export. Run an investigation from Screen 01 first.
      </div>
    );
  }

  const metrics = result.metrics || {};
  const paths = result.candidate_paths || [];

  const handleDownloadJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(result, null, 2));
    const a = document.createElement("a");
    a.href = dataStr;
    a.download = `${result.scenario_id}_analysis.json`;
    a.click();
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-sky-400" />
            06. Report & Evaluation Dashboard
          </h2>
          <p className="text-sm text-slate-400">
            Export machine-readable JSON packages, interactive HTML reports, and inspect benchmark outcomes.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleDownloadJson}
            className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3.5 py-2 rounded-lg text-sm font-semibold transition-colors"
          >
            <FileJson className="w-4 h-4 text-sky-400" />
            <span>Export JSON Package</span>
          </button>

          <a
            href={`http://localhost:8000/api/v1/scenarios/${result.scenario_id}/export?format=html`}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold px-4 py-2 rounded-lg text-sm transition-colors shadow-lg shadow-sky-500/20"
          >
            <FileText className="w-4 h-4" />
            <span>Open Standalone HTML Report</span>
          </a>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-xs uppercase text-slate-400 font-semibold">Graph Nodes</span>
          <div className="text-2xl font-bold text-sky-400 mt-1">{metrics.total_nodes || 0}</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-xs uppercase text-slate-400 font-semibold">Evidence Coverage</span>
          <div className="text-2xl font-bold text-emerald-400 mt-1">
            {Math.round((metrics.evidence_coverage_ratio || 0) * 100)}%
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-xs uppercase text-slate-400 font-semibold">Validation Findings</span>
          <div className="text-2xl font-bold text-amber-400 mt-1">
            {metrics.findings_count?.total || 0}
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <span className="text-xs uppercase text-slate-400 font-semibold">Candidate Paths</span>
          <div className="text-2xl font-bold text-purple-400 mt-1">{paths.length}</div>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
          Alternative Path Explanations & Uncertainty Trajectories
        </h3>

        <div className="space-y-3">
          {paths.map((p) => {
            const isSupported = p.status === "supported";
            const isContra = p.status === "contradicted";

            return (
              <div
                key={p.path_id}
                className={`p-4 rounded-xl border text-sm space-y-2 ${
                  isSupported
                    ? "bg-emerald-950/20 border-emerald-800/60"
                    : isContra
                    ? "bg-red-950/20 border-red-800/60"
                    : "bg-amber-950/20 border-amber-800/60"
                }`}
              >
                <div className="flex justify-between items-center">
                  <span className="font-bold text-slate-100">{p.name}</span>
                  <span
                    className={`text-xs px-2.5 py-0.5 rounded font-bold uppercase ${
                      isSupported
                        ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                        : isContra
                        ? "bg-red-950 text-red-400 border border-red-800"
                        : "bg-amber-950 text-amber-400 border border-amber-800"
                    }`}
                  >
                    {p.status}
                  </span>
                </div>

                <p className="text-xs text-slate-300">{p.confidence_rationale}</p>

                <div className="text-xs text-slate-400 pt-1">
                  <strong className="text-slate-300">Discriminator Telemetry Needed:</strong>{" "}
                  {p.discriminator_evidence.join(", ")}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
