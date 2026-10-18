"use client";

import React, { useState } from "react";
import { Compass, CheckCircle, XCircle, Clock, ExternalLink } from "lucide-react";
import { TechniqueMappingRecord } from "../types";

interface AttackCoverageProps {
  mappings: TechniqueMappingRecord[];
}

export default function AttackCoverage({ mappings }: AttackCoverageProps) {
  const [localMappings, setLocalMappings] = useState<TechniqueMappingRecord[]>(mappings);

  const handleDecision = async (mappingId: string, decision: "accepted" | "rejected") => {
    setLocalMappings((prev) =>
      prev.map((m) => (m.mapping_id === mappingId ? { ...m, status: decision } : m))
    );
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Compass className="w-5 h-5 text-sky-400" />
          05. MITRE ATT&CK® Knowledge Coverage
        </h2>
        <p className="text-sm text-slate-400">
          Reviewed technique mappings, transparent behavioral rationale, and analyst authorization status.
        </p>
      </div>

      <div className="space-y-4">
        {localMappings.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-500">
            No technique mappings available. Run an incident analysis to evaluate ATT&CK techniques.
          </div>
        ) : (
          localMappings.map((m) => {
            const isAccepted = m.status === "accepted";
            const isRejected = m.status === "rejected";

            return (
              <div
                key={m.mapping_id}
                className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <span className="font-mono font-bold text-sky-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800 text-sm">
                      {m.technique_id}
                    </span>
                    <h3 className="font-bold text-slate-100 text-sm">{m.technique_name}</h3>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs px-2.5 py-1 rounded font-semibold uppercase ${
                        isAccepted
                          ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                          : isRejected
                          ? "bg-red-950 text-red-400 border border-red-800"
                          : "bg-amber-950 text-amber-400 border border-amber-800"
                      }`}
                    >
                      {m.status.replace("_", " ")}
                    </span>

                    <button
                      onClick={() => handleDecision(m.mapping_id, "accepted")}
                      className="p-1 hover:text-emerald-400 text-slate-500 transition-colors"
                      title="Accept Mapping"
                    >
                      <CheckCircle className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDecision(m.mapping_id, "rejected")}
                      className="p-1 hover:text-red-400 text-slate-500 transition-colors"
                      title="Reject Mapping"
                    >
                      <XCircle className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                <p className="text-sm text-slate-300">{m.rationale}</p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs bg-slate-950/80 p-3 rounded-lg border border-slate-800/60">
                  <div>
                    <span className="text-slate-500 block uppercase font-semibold">Supporting Evidence:</span>
                    <span className="text-emerald-400 font-mono">
                      {m.supporting_evidence.length > 0 ? m.supporting_evidence.join(", ") : "None directly attached"}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase font-semibold">Missing Evidence Required:</span>
                    <span className="text-amber-300">
                      {m.missing_evidence_required && m.missing_evidence_required.length > 0
                        ? m.missing_evidence_required.join("; ")
                        : "None (Fully substantiated)"}
                    </span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
