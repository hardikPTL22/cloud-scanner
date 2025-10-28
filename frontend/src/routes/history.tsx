import { createFileRoute } from "@tanstack/react-router";
import { useState, useMemo } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  CartesianGrid,
} from "recharts";
import {
  Select,
  SelectTrigger,
  SelectContent,
  SelectItem,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api-client";
import { RESOURCES_MAP } from "@/lib/resource-map";

const SERVICE_MAP: Record<string, string> = {};
Object.entries(RESOURCES_MAP).forEach(([service, vulnerabilities]) => {
  vulnerabilities.forEach((vuln) => {
    SERVICE_MAP[vuln] = service.toUpperCase();
  });
});

const SERVICE_LIST = Object.keys(RESOURCES_MAP).map((s) => s.toUpperCase());

function countFindingsByService(scan: any, service: string) {
  if (!scan.findings) return 0;
  return scan.findings.filter(
    (f: any) => (SERVICE_MAP[f.type] || "OTHER") === service
  ).length;
}

function trendData(scans: any[], service: string) {
  if (!scans || scans.length === 0) return [];

  return scans
    .filter((scan) => scan.completed && scan.created_at)
    .sort((a, b) => {
      const dateA = new Date(a.created_at.$date || a.created_at).getTime();
      const dateB = new Date(b.created_at.$date || b.created_at).getTime();
      return dateA - dateB;
    })
    .map((scan) => {
      const date = new Date(scan.created_at.$date || scan.created_at);
      const formattedDate = date.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
      return {
        date: formattedDate,
        timestamp: date.getTime(),
        count: countFindingsByService(scan, service),
      };
    });
}

export const Route = createFileRoute("/history")({
  component: Page,
});

export function Page() {
  const { data, isLoading } = api.useQuery("get", "/api/scans");
  const [selectedService, setSelectedService] = useState<string>(
    SERVICE_LIST[0]
  );

  const trend = useMemo(
    () => trendData(data?.scans ?? [], selectedService),
    [data, selectedService]
  );

  const allZero = trend.every((d) => d.count === 0);
  const hasNoData = !data || data.scans.length === 0;

  if (isLoading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-8">
        <Card>
          <CardContent className="flex items-center justify-center h-72">
            <div className="text-muted-foreground">Loading scan history...</div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      <Card>
        <CardHeader className="flex flex-col md:flex-row md:items-center md:justify-between">
          <CardTitle>AWS Vulnerability History</CardTitle>
          <Select value={selectedService} onValueChange={setSelectedService}>
            <SelectTrigger className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SERVICE_LIST.map((svc) => (
                <SelectItem key={svc} value={svc}>
                  {svc}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent>
          <div className="h-72 flex items-center justify-center">
            {hasNoData ? (
              <div className="text-muted-foreground text-center w-full">
                No scan history available. Run your first scan to see
                vulnerability trends over time.
              </div>
            ) : allZero ? (
              <div className="text-muted-foreground text-center w-full">
                No vulnerabilities detected for{" "}
                <span className="font-medium">{selectedService}</span> across
                all scans.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trend}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="date"
                    angle={-45}
                    textAnchor="end"
                    height={80}
                    tick={{ fontSize: 12 }}
                  />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="count"
                    name={`${selectedService} Vulnerabilities`}
                    stroke="#6366f1"
                    strokeWidth={2}
                    dot={{ fill: "#6366f1", r: 4 }}
                    activeDot={{ r: 6 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </CardContent>
      </Card>

      {!hasNoData && (
        <Card>
          <CardHeader>
            <CardTitle>Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="p-4 bg-muted rounded-lg">
                <div className="text-sm text-muted-foreground">Total Scans</div>
                <div className="text-2xl font-bold">
                  {data.scans?.length || 0}
                </div>
              </div>
              <div className="p-4 bg-muted rounded-lg">
                <div className="text-sm text-muted-foreground">
                  Latest {selectedService} Issues
                </div>
                <div className="text-2xl font-bold">
                  {trend[trend.length - 1]?.count || 0}
                </div>
              </div>
              <div className="p-4 bg-muted rounded-lg">
                <div className="text-sm text-muted-foreground">Peak Count</div>
                <div className="text-2xl font-bold">
                  {Math.max(...trend.map((d) => d.count), 0)}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
