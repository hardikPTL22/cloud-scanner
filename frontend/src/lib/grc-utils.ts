import type { components } from "@/openapi.d";
import type {
  ComplianceSummary,
  FrameworkScore,
  ComplianceSummary_Legacy,
  FrameworkScore_Legacy,
} from "@/types/grc";

type BaseFinding = components["schemas"]["VulnerabilityFinding"];

type VulnerabilityFinding = BaseFinding & {
  service?: string;
};

function normalizeSeverity(sev?: string) {
  return (sev ?? "").toLowerCase();
}

export function buildComplianceLegacy(
  findings: VulnerabilityFinding[]
): ComplianceSummary_Legacy {
  const normalized = findings.map((f) => ({
    ...f,
    severity: normalizeSeverity(f.severity),
  }));

  const compliantFindings = normalized.filter(
    (f) => f.severity === "low" || f.severity === "medium"
  );

  const nonCompliantFindings = normalized.filter((f) => f.severity === "high");

  const framework: FrameworkScore_Legacy = {
    framework: "ISO 27001",
    total_controls: normalized.length,
    compliant_controls: compliantFindings.length,
    non_compliant_controls: nonCompliantFindings.length,
    compliance_percentage: normalized.length
      ? Math.round((compliantFindings.length / normalized.length) * 100)
      : 0,
    controls: normalized.map((f, idx) => ({
      id: `ISO-${idx + 1}`,
      title: f.name,
      status: f.severity === "high" ? "non-compliant" : "compliant",
      severity: f.severity,
      service: f.service ?? "unknown",
    })),
  };

  return {
    total_controls: framework.total_controls,
    compliant_controls: framework.compliant_controls,
    non_compliant_controls: framework.non_compliant_controls,
    compliance_percentage: framework.compliance_percentage,
    frameworks: [framework],
  };
}

export function buildCompliance(
  findings: VulnerabilityFinding[]
): ComplianceSummary {
  const normalized = findings.map((f) => ({
    ...f,
    severity: normalizeSeverity(f.severity),
  }));

  const compliantFindings = normalized.filter(
    (f) => f.severity === "low" || f.severity === "medium"
  );

  const nonCompliantFindings = normalized.filter((f) => f.severity === "high");

  const totalControls = normalized.length;
  const compliantCount = compliantFindings.length;
  const nonCompliantCount = nonCompliantFindings.length;

  const compliancePercent = totalControls
    ? Math.round((compliantCount / totalControls) * 100)
    : 0;

  const createFrameworkScore = (): FrameworkScore => ({
    total_controls: totalControls,
    compliant: compliantCount,
    non_compliant: nonCompliantCount,
    compliance_percent: compliancePercent,
  });

  return {
    overall_compliance: compliancePercent,
    frameworks: {
      iso27001: createFrameworkScore(),
      nist_csf: createFrameworkScore(),
      cis_aws: createFrameworkScore(),
    },
    control_status: {
      compliant: compliantCount,
      non_compliant: nonCompliantCount,
    },
  };
}
