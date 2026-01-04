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
