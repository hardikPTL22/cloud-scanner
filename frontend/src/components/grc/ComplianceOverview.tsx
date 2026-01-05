import type { GRCDashboardResponse } from "@/types/grc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import {
  ShieldCheck,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
} from "lucide-react";

export default function ComplianceOverview({
  data,
}: {
  data: GRCDashboardResponse;
}) {
  const {
    compliance_summary,
    control_effectiveness,
    risk_distribution,
    total_risk_score,
    average_risk_score,
  } = data;

  const getComplianceColor = (percentage: number) => {
    if (percentage >= 90) return "text-green-600";
    if (percentage >= 70) return "text-yellow-600";
    return "text-red-600";
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case "critical":
        return "bg-purple-600";
      case "high":
        return "bg-red-600";
      case "medium":
        return "bg-yellow-600";
      case "low":
        return "bg-blue-600";
      default:
        return "bg-gray-600";
    }
  };

  const overallEffectiveness = control_effectiveness?.overall;

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">
            Overall Compliance
          </CardTitle>
          <ShieldCheck className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div
            className={`text-2xl font-bold ${getComplianceColor(
              compliance_summary.overall_compliance
            )}`}
          >
            {compliance_summary.overall_compliance.toFixed(1)}%
          </div>
          <Progress
            value={compliance_summary.overall_compliance}
            className="mt-2"
          />
          <p className="text-xs text-muted-foreground mt-2">
            {compliance_summary.control_status.compliant} compliant /{" "}
            {compliance_summary.control_status.non_compliant} non-compliant
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
          <AlertTriangle className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">
            {total_risk_score.toFixed(1)}
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            Average: {average_risk_score.toFixed(2)} per finding
          </p>
          <div className="flex gap-1 mt-2">
            {(Object.entries(risk_distribution) as [string, number][]).map(
              ([level, count]) =>
                count > 0 && (
                  <Badge
                    key={level}
                    variant="outline"
                    className={`${getRiskColor(level)} text-white text-xs`}
                  >
                    {count}
                  </Badge>
                )
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">
            Control Effectiveness
          </CardTitle>
          {overallEffectiveness &&
            overallEffectiveness.improvement_rate !== undefined &&
            (overallEffectiveness.improvement_rate >= 0 ? (
              <TrendingUp className="h-4 w-4 text-green-600" />
            ) : (
              <TrendingDown className="h-4 w-4 text-red-600" />
            ))}
        </CardHeader>
        <CardContent>
          {overallEffectiveness ? (
            <>
              <div className="text-2xl font-bold">
                {overallEffectiveness.control_effectiveness_rating.toFixed(1)}%
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                {overallEffectiveness.improvement_rate !== undefined && (
                  <span
                    className={
                      overallEffectiveness.improvement_rate >= 0
                        ? "text-green-600"
                        : "text-red-600"
                    }
                  >
                    {overallEffectiveness.improvement_rate > 0 ? "+" : ""}
                    {overallEffectiveness.improvement_rate.toFixed(1)}% change
                  </span>
                )}
              </p>
              <p className="text-xs text-muted-foreground">
                {overallEffectiveness.effective_controls} /{" "}
                {overallEffectiveness.total_controls} effective
              </p>
            </>
          ) : (
            <div className="text-sm text-muted-foreground">
              Insufficient data. Run more scans to track effectiveness.
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Frameworks</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs">ISO 27001</span>
              <span
                className={`text-xs font-medium ${getComplianceColor(
                  compliance_summary.frameworks.iso27001.compliance_percent
                )}`}
              >
                {compliance_summary.frameworks.iso27001.compliance_percent.toFixed(
                  0
                )}
                %
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-xs">NIST CSF</span>
              <span
                className={`text-xs font-medium ${getComplianceColor(
                  compliance_summary.frameworks.nist_csf.compliance_percent
                )}`}
              >
                {compliance_summary.frameworks.nist_csf.compliance_percent.toFixed(
                  0
                )}
                %
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-xs">CIS AWS</span>
              <span
                className={`text-xs font-medium ${getComplianceColor(
                  compliance_summary.frameworks.cis_aws.compliance_percent
                )}`}
              >
                {compliance_summary.frameworks.cis_aws.compliance_percent.toFixed(
                  0
                )}
                %
              </span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
