import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { GRCDashboardResponse } from "@/types/grc";

export default function RiskHeatmap({ data }: { data: GRCDashboardResponse }) {
  const { risk_distribution, total_risk_score, average_risk_score } = data;

  const total = (Object.values(risk_distribution) as number[]).reduce(
    (sum: number, count: number) => sum + count,
    0
  );

  const getRiskData = () => [
    {
      level: "Critical",
      count: risk_distribution.critical,
      color: "bg-purple-600",
      textColor: "text-purple-600",
    },
    {
      level: "High",
      count: risk_distribution.high,
      color: "bg-red-600",
      textColor: "text-red-600",
    },
    {
      level: "Medium",
      count: risk_distribution.medium,
      color: "bg-yellow-600",
      textColor: "text-yellow-600",
    },
    {
      level: "Low",
      count: risk_distribution.low,
      color: "bg-blue-600",
      textColor: "text-blue-600",
    },
    {
      level: "Info",
      count: risk_distribution.informational,
      color: "bg-gray-600",
      textColor: "text-gray-600",
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Risk Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-center">
            <div className="p-4 border rounded-lg">
              <div className="text-2xl font-bold">
                {total_risk_score.toFixed(1)}
              </div>
              <div className="text-xs text-muted-foreground">
                Total Risk Score
              </div>
            </div>
            <div className="p-4 border rounded-lg">
              <div className="text-2xl font-bold">
                {average_risk_score.toFixed(2)}
              </div>
              <div className="text-xs text-muted-foreground">
                Avg Risk Score
              </div>
            </div>
          </div>

          <div className="space-y-3">
            {getRiskData().map((risk) => {
              const percentage = total > 0 ? (risk.count / total) * 100 : 0;
              return (
                <div key={risk.level} className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <span className={`font-medium ${risk.textColor}`}>
                      {risk.level}
                    </span>
                    <span className="text-muted-foreground">
                      {risk.count} ({percentage.toFixed(0)}%)
                    </span>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${risk.color} transition-all duration-500`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pt-4 border-t">
            <div className="text-sm text-muted-foreground">
              Total Findings:{" "}
              <span className="font-medium text-foreground">{total}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
