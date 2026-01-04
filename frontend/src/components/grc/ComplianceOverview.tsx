import type { ComplianceSummary } from "@/lib/grc-types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

export default function ComplianceOverview({
  summary,
}: {
  summary: ComplianceSummary;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Overall Compliance</CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="text-3xl font-bold">
          {summary.compliance_percentage}%
        </div>

        <Progress value={summary.compliance_percentage} />

        <div className="grid grid-cols-3 gap-4 text-sm">
          <div>
            <p className="font-medium">Total Controls</p>
            <p>{summary.total_controls}</p>
          </div>

          <div>
            <p className="font-medium text-green-600">Compliant</p>
            <p>{summary.compliant_controls}</p>
          </div>

          <div>
            <p className="font-medium text-red-600">Non-Compliant</p>
            <p>{summary.non_compliant_controls}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
