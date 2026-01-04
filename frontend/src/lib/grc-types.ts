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

export type FrameworkScore = {
  framework: string;
  total_controls: number;
  compliant_controls: number;
  non_compliant_controls: number;
  compliance_percentage: number;
  controls: ControlItem[];
};

export type ComplianceSummary = {
  total_controls: number;
  compliant_controls: number;
  non_compliant_controls: number;
  compliance_percentage: number;
  frameworks: FrameworkScore[];
};

export type ComplianceTrendPoint = {
  scan_id: string;
  date: string;
  compliance_percentage: number;
  compliant_controls: number;
  non_compliant_controls: number;
};
