"use client";

import React, { useState } from "react";
import { Play, UploadCloud, Database, CheckCircle2 } from "lucide-react";
import { Scenario } from "../types";

interface ScenarioWorkspaceProps {
  onRunAnalysis: (bundleJson?: string) => Promise<void>;
  isLoading: boolean;
  currentScenario: Scenario | null;
}

export default function ScenarioWorkspace({
  onRunAnalysis,
  isLoading,
  currentScenario,
}: ScenarioWorkspaceProps) {
  const [scenarioName, setScenarioName] = useState(
    currentScenario?.name || "Incident INC-2026-8812: Suspicious Credential Access & Exfil"
  );
  const [objective, setObjective] = useState(
    currentScenario?.objective || "Determine if foreign auth event enabled billing portal and S3 data dump."
  );
  const [jsonInput, setJsonInput] = useState(`{
  "scenario": {
    "id": "INC-2026-8812",
    "name": "Suspected Employee Account Misuse & Sensitive Data Access",
    "objective": "Determine if foreign auth event enabled billing portal and S3 data dump."
  },
  "assets": [
    {"id": "usr-bob", "name": "bob.miller@megacorp.internal", "asset_type": "identity"},
    {"id": "app-billing", "name": "BillingPortal-Internal", "asset_type": "application"},
    {"id": "db-vault", "name": "FinancialRecords-EncryptedBucket", "asset_type": "cloud_resource"}
  ],
  "observations": [
    {
      "id": "obs-101",
      "timestamp": "2026-10-18T14:00:00Z",
      "category": "auth",
      "description": "Unusual sign-in from foreign IP 185.220.101.5 for bob.miller@megacorp.internal",
      "actor_identity": "bob.miller@megacorp.internal",
      "asset_id": "usr-bob"
    },
    {
      "id": "obs-102",
      "timestamp": "2026-10-18T14:04:00Z",
      "category": "endpoint",
      "description": "PowerShell script executed Get-Credential and web session handoff to BillingPortal",
      "actor_identity": "bob.miller@megacorp.internal",
      "asset_id": "app-billing"
    },
    {
      "id": "obs-103",
      "timestamp": "2026-10-18T14:10:00Z",
      "category": "cloud",
      "description": "GetObject bulk export of 12,000 records from FinancialRecords-EncryptedBucket",
      "actor_identity": "bob.miller@megacorp.internal",
      "asset_id": "db-vault"
    }
  ],
  "hypotheses": [
    {"id": "step-1", "title": "Credential Access / Account Takeover", "stage": "initial-access"},
    {"id": "step-2", "title": "Execution via PowerShell Web Request", "stage": "execution"},
    {"id": "step-3", "title": "Cloud Storage Exfiltration", "stage": "collection"}
  ],
  "controls": [
    {"id": "ctrl-mfa", "name": "Conditional Access & MFA Policy", "category": "preventive", "state": "confirmed_present"},
    {"id": "ctrl-dlp", "name": "Cloud DLP Sensitive Object Access Monitoring", "category": "detective", "state": "confirmed_present"}
  ],
  "explicit_edges": [
    {"id": "e1", "source": "step-1", "target": "step-2", "edge_type": "ENABLES"},
    {"id": "e2", "source": "step-2", "target": "step-3", "edge_type": "ENABLES"},
    {"id": "e3", "source": "step-1", "target": "obs-101", "edge_type": "OBSERVED_AS"},
    {"id": "e4", "source": "step-2", "target": "obs-102", "edge_type": "OBSERVED_AS"},
    {"id": "e5", "source": "step-3", "target": "obs-103", "edge_type": "OBSERVED_AS"},
    {"id": "e6", "source": "step-1", "target": "ctrl-mfa", "edge_type": "MITIGATED_BY"},
    {"id": "e7", "source": "step-3", "target": "ctrl-dlp", "edge_type": "MITIGATED_BY"}
  ]
}`);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-slate-100">01. Scenario Workspace</h2>
          <p className="text-sm text-slate-400">
            Define incident metadata, register evidence sources, and launch the reasoning engine.
          </p>
        </div>
        <button
          onClick={() => onRunAnalysis(jsonInput)}
          disabled={isLoading}
          className="flex items-center gap-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold px-4 py-2 rounded-lg transition-colors shadow-lg shadow-sky-500/20 disabled:opacity-50"
        >
          <Play className="w-4 h-4 fill-current" />
          <span>{isLoading ? "Running Reasoning Engine..." : "Execute Reasoning Engine"}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Database className="w-4 h-4 text-sky-400" />
              Scenario Configuration
            </h3>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Investigation Name</label>
              <input
                type="text"
                value={scenarioName}
                onChange={(e) => setScenarioName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">Analysis Objective</label>
              <textarea
                rows={3}
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div className="pt-2 border-t border-slate-800">
              <span className="text-xs text-slate-400 font-semibold block mb-2">Active Controls Verified</span>
              <div className="space-y-1.5 text-xs text-slate-300">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Conditional Access & MFA Policy</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Cloud DLP Access Monitoring</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex justify-between items-center">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <UploadCloud className="w-4 h-4 text-sky-400" />
                Evidence Bundle Ingestion (JSON Schema)
              </h3>
              <span className="text-xs text-slate-500 font-mono">Pydantic v2 Validated</span>
            </div>

            <textarea
              rows={16}
              value={jsonInput}
              onChange={(e) => setJsonInput(e.target.value)}
              className="w-full font-mono text-xs bg-slate-950 border border-slate-800 rounded-lg p-3 text-sky-300 focus:outline-none focus:border-sky-500 leading-relaxed"
            />
          </div>
        </div>
      </div>
    </div>
  );
}
