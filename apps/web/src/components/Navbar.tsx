"use client";

import React from "react";
import { Shield, Network, FileSearch, AlertCircle, Compass, FileText } from "lucide-react";

interface NavbarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
  scenarioId: string;
}

export default function Navbar({ currentTab, onTabChange, scenarioId }: NavbarProps) {
  const tabs = [
    { id: "workspace", label: "01. Workspace", icon: Shield },
    { id: "evidence", label: "02. Evidence Explorer", icon: FileSearch },
    { id: "graph", label: "03. Attack Graph", icon: Network },
    { id: "findings", label: "04. Finding Details", icon: AlertCircle },
    { id: "attack", label: "05. ATT&CK Coverage", icon: Compass },
    { id: "report", label: "06. Report & Evaluation", icon: FileText },
  ];

  return (
    <header className="bg-slate-900 border-b border-slate-800 px-6 py-4 flex flex-col md:flex-row justify-between items-center gap-4">
      <div className="flex items-center gap-3">
        <div className="bg-sky-500/20 text-sky-400 p-2 rounded-lg border border-sky-500/30">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            AttackPath Intelligence
            <span className="text-xs bg-sky-950 text-sky-300 px-2 py-0.5 rounded border border-sky-700">v1.0</span>
          </h1>
          <p className="text-xs text-slate-400">
            Active Scenario: <strong className="text-slate-200">{scenarioId || "None Selected"}</strong>
          </p>
        </div>
      </div>

      <nav className="flex items-center gap-1 overflow-x-auto max-w-full">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = currentTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                isActive
                  ? "bg-sky-500 text-slate-950 font-semibold shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>
    </header>
  );
}
