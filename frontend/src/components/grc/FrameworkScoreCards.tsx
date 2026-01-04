import type { FrameworkScore } from "@/lib/grc-types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

export default function FrameworkScoreCards({
  frameworks,
}: {
  frameworks: FrameworkScore[];
}) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {frameworks.map((fw) => (
        <Card key={fw.framework}>
          <CardHeader>
            <CardTitle className="uppercase">{fw.framework}</CardTitle>
          </CardHeader>

          <CardContent className="space-y-3">
            <div className="text-2xl font-bold">
              {fw.compliance_percentage}%
            </div>

            <Progress value={fw.compliance_percentage} />

            <div className="text-sm space-y-1">
              <p>Total Controls: {fw.total_controls}</p>
              <p className="text-green-600">
                Compliant: {fw.compliant_controls}
              </p>
              <p className="text-red-600">
                Non-Compliant: {fw.non_compliant_controls}
              </p>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
