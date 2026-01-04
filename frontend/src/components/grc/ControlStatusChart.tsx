import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const COLORS = ["#22c55e", "#ef4444"];

export default function ControlStatusChart({
  status,
}: {
  status: { compliant: number; non_compliant: number };
}) {
  const data = [
    { name: "Compliant", value: status.compliant },
    { name: "Non-Compliant", value: status.non_compliant },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Control Status</CardTitle>
      </CardHeader>
      <CardContent className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" label>
              {data.map((_, i) => (
                <Cell key={i} fill={COLORS[i]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
