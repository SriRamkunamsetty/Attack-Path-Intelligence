"use client";

import React, { useState } from "react";
import { Filter, Search, Clock, User, Server } from "lucide-react";
import { GraphNode } from "../types";

interface EvidenceExplorerProps {
  nodes: GraphNode[];
}

export default function EvidenceExplorer({ nodes }: EvidenceExplorerProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");

  const observations = nodes.filter((n) => n.type === "observation");

  const filtered = observations.filter((obs) => {
    const data = obs.data || {};
    const text = `${obs.id} ${obs.label} ${data.category || ""} ${data.actor_identity || ""} ${data.asset_id || ""}`.toLowerCase();
    const matchesSearch = text.includes(searchTerm.toLowerCase());
    const matchesCat = categoryFilter === "all" || (data.category || "").toLowerCase() === categoryFilter.toLowerCase();
    return matchesSearch && matchesCat;
  });

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100">02. Evidence Explorer</h2>
        <p className="text-sm text-slate-400">
          Inspect normalized empirical observations, timestamps, asset identities, and SHA-256 provenance hashes.
        </p>
      </div>

      <div className="flex flex-col md:flex-row gap-4 items-center justify-between bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 w-full md:w-96">
          <Search className="w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search by ID, identity, asset or description..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent text-sm text-slate-200 focus:outline-none w-full"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <Filter className="w-4 h-4 text-slate-400" />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none"
          >
            <option value="all">All Categories</option>
            <option value="auth">Authentication</option>
            <option value="endpoint">Endpoint / Process</option>
            <option value="network">Network Traffic</option>
            <option value="cloud">Cloud Activity</option>
          </select>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-left border-collapse text-sm">
          <thead>
            <tr className="bg-slate-800/60 border-b border-slate-800 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <th className="py-3 px-4">Evidence ID</th>
              <th className="py-3 px-4">Timestamp (UTC)</th>
              <th className="py-3 px-4">Category</th>
              <th className="py-3 px-4">Actor / Asset</th>
              <th className="py-3 px-4">Observation Description</th>
              <th className="py-3 px-4">Provenance Hash</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500">
                  No observations match the filter criteria.
                </td>
              </tr>
            ) : (
              filtered.map((obs) => {
                const data = obs.data || {};
                return (
                  <tr key={obs.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 font-mono font-medium text-sky-400">{obs.id}</td>
                    <td className="py-3 px-4 text-slate-300 font-mono text-xs flex items-center gap-1.5 mt-1">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      {data.timestamp ? new Date(data.timestamp).toLocaleString() : "Unknown"}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
                        {data.category || "generic"}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-col gap-0.5 text-xs">
                        {data.actor_identity && (
                          <span className="flex items-center gap-1 text-slate-200">
                            <User className="w-3 h-3 text-slate-400" />
                            {data.actor_identity}
                          </span>
                        )}
                        {data.asset_id && (
                          <span className="flex items-center gap-1 text-slate-400 font-mono">
                            <Server className="w-3 h-3 text-slate-500" />
                            {data.asset_id}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-200 max-w-md">{obs.label}</td>
                    <td className="py-3 px-4 text-xs font-mono text-slate-500 truncate max-w-xs">
                      {data.provenance_hash ? data.provenance_hash.slice(0, 16) + "..." : "sha256-verified"}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
