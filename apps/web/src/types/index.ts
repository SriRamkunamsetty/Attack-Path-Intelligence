export type NodeType = "asset" | "observation" | "attack_step" | "technique" | "security_control" | "finding";

export type EdgeType = "PRECEDES" | "ENABLES" | "OBSERVED_AS" | "MAPPED_TO" | "MITIGATED_BY" | "CONTRADICTS" | "DEPENDS_ON";

export type Severity = "ERROR" | "WARNING" | "INFO";

export type PathStatus = "supported" | "partially_supported" | "unsubstantiated" | "contradicted";

export interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  data: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  edge_type: EdgeType;
  evidence_refs: string[];
  metadata: Record<string, any>;
}

export interface AttackGraphExport {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Finding {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  affected_node_ids: string[];
  affected_edge_ids: string[];
  evidence_refs: string[];
  explanation: string;
  remediation_guidance: string;
}

export interface CandidatePath {
  path_id: string;
  name: string;
  step_ids: string[];
  edge_ids: string[];
  status: PathStatus;
  confidence_rationale: string;
  supporting_observations: string[];
  required_assumptions: string[];
  missing_evidence: string[];
  conflicting_evidence: string[];
  discriminator_evidence: string[];
  potential_impact: string;
}

export interface TechniqueMappingRecord {
  mapping_id: string;
  target_id: string;
  technique_id: string;
  technique_name: string;
  rationale: string;
  supporting_evidence: string[];
  missing_evidence_required: string[];
  status: "requires_review" | "accepted" | "rejected";
  reviewer_notes?: string;
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  objective: string;
  created_at: string;
  updated_at: string;
}

export interface AnalysisResult {
  scenario_id: string;
  timestamp: string;
  rule_engine_version: string;
  dataset_version: string;
  graph: AttackGraphExport;
  findings: Finding[];
  candidate_paths: CandidatePath[];
  technique_mappings: TechniqueMappingRecord[];
  metrics: Record<string, any>;
}
