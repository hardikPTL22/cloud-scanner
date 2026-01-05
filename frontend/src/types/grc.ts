export type ControlStatus = "compliant" | "non-compliant" | "accepted-risk";

export type ControlItem = {
  id: string;
  title: string;
  status: ControlStatus;
  severity: string;
  service: string;
  iso?: string;
  nist?: string;
  cis?: string;
};

export type FrameworkScore_Legacy = {
  framework: string;
  total_controls: number;
  compliant_controls: number;
  non_compliant_controls: number;
  compliance_percentage: number;
  controls: ControlItem[];
};

export type ComplianceSummary_Legacy = {
  total_controls: number;
  compliant_controls: number;
  non_compliant_controls: number;
  compliance_percentage: number;
  frameworks: FrameworkScore_Legacy[];
};

export type ComplianceTrendPoint_Legacy = {
  scan_id: string;
  date: string;
  compliance_percentage: number;
  compliant_controls: number;
  non_compliant_controls: number;
};

export interface FrameworkScore {
  total_controls: number;
  compliant: number;
  non_compliant: number;
  compliance_percent: number;
}

export interface ComplianceSummary {
  overall_compliance: number;
  frameworks: {
    iso27001: FrameworkScore;
    nist_csf: FrameworkScore;
    cis_aws: FrameworkScore;
  };
  control_status: {
    compliant: number;
    non_compliant: number;
  };
}

export interface RiskScore {
  score: number;
  level: "critical" | "high" | "medium" | "low" | "informational";
  cvss_base: number;
  impact_factor: number;
  exploitability_factor: number;
}

export interface NonCompliantControl {
  control_id: string;
  framework: string;
  title: string;
  service: string;
  severity: string;
  risk_score: RiskScore;
  resource_ids: string[];
  finding_types: string[];
  finding_count: number;
}

export interface ControlEffectiveness {
  control_effectiveness_rating: number;
  improvement_rate: number;
  overall_trend?: number;
  stability_score?: number;
  total_controls: number;
  effective_controls: number;
  failed_controls: number;
  scan_count?: number;
  period_start?: string;
  period_end?: string;
  frameworks_tracked?: number;
}

export interface GRCDashboardResponse {
  compliance_summary: ComplianceSummary;
  control_effectiveness: {
    iso27001?: ControlEffectiveness;
    nist_csf?: ControlEffectiveness;
    cis_aws?: ControlEffectiveness;
    overall?: ControlEffectiveness;
  } | null;
  non_compliant_controls: NonCompliantControl[];
  risk_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  total_risk_score: number;
  average_risk_score: number;
  findings_count: number;
  controls_failed: number;
}

export interface ComplianceTrendPoint {
  scan_id: string;
  date: string;
  compliance_percentage: number;
  compliant_controls: number;
  non_compliant_controls: number;
  frameworks: {
    iso27001: number;
    nist_csf: number;
    cis_aws: number;
  };
}

export interface ComplianceTrendResponse {
  trend: ComplianceTrendPoint[];
}

export type TrendPoint = {
  date: string;
  compliance: number;
};
