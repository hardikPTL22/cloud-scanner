import type { ComplianceSummary, ControlEffectiveness } from "@/types/grc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

export default function FrameworkScoreCards({
  compliance,
  effectiveness,
}: {
  compliance: ComplianceSummary;
  effectiveness: {
    iso27001?: ControlEffectiveness;
    nist_csf?: ControlEffectiveness;
    cis_aws?: ControlEffectiveness;
  } | null;
}) {
  const frameworks = [
    {
      key: "iso27001",
      name: "ISO 27001",
      description: "Information Security Management",
      color: "border-blue-500",
    },
    {
      key: "nist_csf",
      name: "NIST CSF",
      description: "Cybersecurity Framework",
      color: "border-purple-500",
    },
    {
      key: "cis_aws",
      name: "CIS AWS",
      description: "AWS Foundations Benchmark",
      color: "border-orange-500",
    },
  ];

  const getComplianceColor = (percentage: number) => {
    if (percentage >= 90) return "text-green-600";
    if (percentage >= 70) return "text-yellow-600";
    return "text-red-600";
  };

  const getTrendIcon = (rate?: number) => {
    if (!rate || rate === 0) return <Minus className="h-4 w-4 text-gray-500" />;
    if (rate > 0) return <TrendingUp className="h-4 w-4 text-green-600" />;
    return <TrendingDown className="h-4 w-4 text-red-600" />;
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {frameworks.map((framework) => {
        const score =
          compliance.frameworks[
            framework.key as keyof typeof compliance.frameworks
          ];
        const effectivenessData =
          effectiveness?.[framework.key as keyof typeof effectiveness];

        return (
          <Card key={framework.key} className={`border-l-4 ${framework.color}`}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg">{framework.name}</CardTitle>
                {effectivenessData &&
                  getTrendIcon(effectivenessData.improvement_rate)}
              </div>
              <p className="text-xs text-muted-foreground">
                {framework.description}
              </p>
            </CardHeader>

            <CardContent className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Compliance</span>
                  <span
                    className={`text-2xl font-bold ${getComplianceColor(
                      score.compliance_percent
                    )}`}
                  >
                    {score.compliance_percent.toFixed(0)}%
                  </span>
                </div>
                <Progress value={score.compliance_percent} className="h-2" />
              </div>

              <div className="grid grid-cols-3 gap-2 text-center text-sm">
                <div className="space-y-1">
                  <div className="text-xs text-muted-foreground">Total</div>
                  <Badge variant="outline">{score.total_controls}</Badge>
                </div>
                <div className="space-y-1">
                  <div className="text-xs text-muted-foreground">Pass</div>
                  <Badge className="bg-green-600 hover:bg-green-700">
                    {score.compliant}
                  </Badge>
                </div>
                <div className="space-y-1">
                  <div className="text-xs text-muted-foreground">Fail</div>
                  <Badge className="bg-red-600 hover:bg-red-700">
                    {score.non_compliant}
                  </Badge>
                </div>
              </div>

              {effectivenessData && (
                <div className="pt-3 border-t space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">Effectiveness</span>
                    <span className="font-medium">
                      {effectivenessData.control_effectiveness_rating.toFixed(
                        1
                      )}
                      %
                    </span>
                  </div>
                  {effectivenessData.improvement_rate !== undefined && (
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">Trend</span>
                      <span
                        className={
                          effectivenessData.improvement_rate >= 0
                            ? "text-green-600"
                            : "text-red-600"
                        }
                      >
                        {effectivenessData.improvement_rate > 0 ? "+" : ""}
                        {effectivenessData.improvement_rate.toFixed(1)}%
                      </span>
                    </div>
                  )}
                  {effectivenessData.stability_score !== undefined && (
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">Stability</span>
                      <span className="font-medium">
                        {effectivenessData.stability_score.toFixed(0)}%
                      </span>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
