import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type RiskCell = {
  impact: "Low" | "Medium" | "High";
  likelihood: "Low" | "Medium" | "High";
  count: number;
};

const COLORS: Record<number, string> = {
  0: "bg-green-100",
  1: "bg-yellow-100",
  2: "bg-orange-200",
  3: "bg-red-300",
};

function getColor(count: number) {
  if (count >= 6) return COLORS[3];
  if (count >= 4) return COLORS[2];
  if (count >= 2) return COLORS[1];
  return COLORS[0];
}

export default function RiskHeatmap({ data }: { data: RiskCell[] }) {
  const impacts: RiskCell["impact"][] = ["Low", "Medium", "High"];
  const likelihoods: RiskCell["likelihood"][] = ["Low", "Medium", "High"];

  const findCell = (impact: string, likelihood: string) =>
    data.find((d) => d.impact === impact && d.likelihood === likelihood)
      ?.count || 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Risk Heatmap</CardTitle>
      </CardHeader>

      <CardContent>
        <div className="grid grid-cols-4 gap-2 text-center text-sm">
          <div></div>
          {likelihoods.map((l) => (
            <div key={l} className="font-semibold">
              {l}
            </div>
          ))}

          {impacts.map((impact) => (
            <>
              <div key={impact} className="font-semibold">
                {impact}
              </div>
              {likelihoods.map((likelihood) => {
                const count = findCell(impact, likelihood);
                return (
                  <div
                    key={`${impact}-${likelihood}`}
                    className={`h-16 flex items-center justify-center rounded ${getColor(
                      count
                    )}`}
                  >
                    {count}
                  </div>
                );
              })}
            </>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
