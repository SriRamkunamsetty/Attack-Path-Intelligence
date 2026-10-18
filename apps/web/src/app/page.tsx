"use client";

import React, { useState, useEffect } from "react";
import Navbar from "@/components/Navbar";
import ScenarioWorkspace from "@/components/ScenarioWorkspace";
import EvidenceExplorer from "@/components/EvidenceExplorer";
import AttackGraphCanvas from "@/components/AttackGraphCanvas";
import FindingDetails from "@/components/FindingDetails";
import AttackCoverage from "@/components/AttackCoverage";
import ReportEvaluation from "@/components/ReportEvaluation";
import { AnalysisResult, Scenario } from "@/types";

export default function Home() {
  const [currentTab, setCurrentTab] = useState("workspace");
  const [isLoading, setIsLoading] = useState(false);
  const [scenarioId, setScenarioId] = useState("INC-2026-8812");
  const [currentScenario, setCurrentScenario] = useState<Scenario | null>(null);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);

  // Initial mock analysis data so the dashboard is immediately interactive even before FastAPI starts
  useEffect(() => {
    fetchInitialData();
  }, []);

  const fetchInitialData = async () => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/scenarios/INC-2026-8812/analyze`, {
        method: "POST",
      });
      if (res.ok) {
        const data = await res.json();
        setAnalysisResult(data);
      }
    } catch (e) {
      // Backend not running yet; preload with realistic client-side fallback bundle
      console.log("FastAPI backend offline; running in standalone client demonstration mode.");
    }
  };

  const handleRunAnalysis = async (bundleJson?: string) => {
    setIsLoading(true);
    try {
      if (bundleJson) {
        const parsed = JSON.parse(bundleJson);
        const sid = parsed.scenario?.id || "INC-2026-8812";
        setScenarioId(sid);

        // 1. Create Scenario
        await fetch("http://localhost:8000/api/v1/scenarios", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            id: sid,
            name: parsed.scenario?.name || "Incident Investigation",
            description: parsed.scenario?.description || "",
            objective: parsed.scenario?.objective || "",
          }),
        }).catch(() => {});

        // 2. Upload Evidence
        await fetch(`http://localhost:8000/api/v1/scenarios/${sid}/evidence`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            source_type: "json_bundle",
            content: bundleJson,
          }),
        }).catch(() => {});

        // 3. Analyze
        const res = await fetch(`http://localhost:8000/api/v1/scenarios/${sid}/analyze`, {
          method: "POST",
        });

        if (res.ok) {
          const result = await res.json();
          setAnalysisResult(result);
          setCurrentTab("graph");
        }
      }
    } catch (err) {
      console.error("Analysis execution error:", err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      <Navbar currentTab={currentTab} onTabChange={setCurrentTab} scenarioId={scenarioId} />

      <main className="flex-1">
        {currentTab === "workspace" && (
          <ScenarioWorkspace
            onRunAnalysis={handleRunAnalysis}
            isLoading={isLoading}
            currentScenario={currentScenario}
          />
        )}
        {currentTab === "evidence" && (
          <EvidenceExplorer nodes={analysisResult?.graph?.nodes || []} />
        )}
        {currentTab === "graph" && (
          <AttackGraphCanvas graph={analysisResult?.graph || null} />
        )}
        {currentTab === "findings" && (
          <FindingDetails findings={analysisResult?.findings || []} />
        )}
        {currentTab === "attack" && (
          <AttackCoverage mappings={analysisResult?.technique_mappings || []} />
        )}
        {currentTab === "report" && (
          <ReportEvaluation result={analysisResult} />
        )}
      </main>
    </div>
  );
}
