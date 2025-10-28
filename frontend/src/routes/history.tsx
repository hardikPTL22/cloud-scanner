import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useMemo } from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid } from "recharts";
import {
  Select,
  SelectTrigger,
  SelectContent,
  SelectItem,
  SelectValue,
  SelectSeparator,
} from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  type ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
} from "@/components/ui/chart";
import { api } from "@/lib/api-client";
import { RESOURCES_MAP } from "@/lib/resource-map";
import { ArrowUpRight } from "lucide-react";

const SERVICE_MAP: Record<string, string> = {};
Object.entries(RESOURCES_MAP).forEach(([service, vulnerabilities]) => {
  vulnerabilities.forEach((vuln) => {
    SERVICE_MAP[vuln] = service.toUpperCase();
  });
});

const SERVICE_LIST = Object.keys(RESOURCES_MAP).map((s) => s.toUpperCase());

const SERVICE_COLORS = [
  "#6366f1",
  "#ec4899",
  "#f59e0b",
  "#10b981",
  "#8b5cf6",
  "#ef4444",
  "#06b6d4",
  "#84cc16",
  "#f97316",
  "#14b8a6",
  "#a855f7",
  "#eab308",
  "#22c55e",
  "#3b82f6",
  "#d946ef",
];

function countFindingsByService(scan: any, service: string) {
  if (!scan.findings) return 0;
  return scan.findings.filter(
    (f: any) => (SERVICE_MAP[f.type] || "OTHER") === service
  ).length;
}

function trendData(scans: any[], service: string) {
  if (!scans || scans.length === 0) return [];

  return scans
    .filter((scan) => scan.created_at)
    .sort((a, b) => {
      const dateA = new Date(a.created_at).getTime();
      const dateB = new Date(b.created_at).getTime();
      return dateA - dateB;
    })
    .map((scan) => {
      const date = new Date(scan.created_at);
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

function allServicesTrendData(scans: any[]) {
  if (!scans || scans.length === 0) return [];

  return scans
    .filter((scan) => scan.created_at)
    .sort((a, b) => {
      const dateA = new Date(a.created_at).getTime();
      const dateB = new Date(b.created_at).getTime();
      return dateA - dateB;
    })
    .map((scan) => {
      const date = new Date(scan.created_at);
      const formattedDate = date.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });

      const dataPoint: any = {
        date: formattedDate,
        timestamp: date.getTime(),
      };

      SERVICE_LIST.forEach((service) => {
        dataPoint[service] = countFindingsByService(scan, service);
      });

      return dataPoint;
    });
}

function getSeverityCount(findings: any[], severity: string) {
  if (!findings) return 0;
  return findings.filter((f) => f.severity === severity).length;
}

export const Route = createFileRoute("/history")({
  component: Page,
});

export function Page() {
  const { data, isLoading } = api.useQuery("get", "/api/scans");
  const [selectedService, setSelectedService] = useState<string | undefined>(
    undefined
  );

  const trend = useMemo(
    () =>
      selectedService ? trendData(data?.scans ?? [], selectedService) : [],
    [data, selectedService]
  );

  const allServicesTrend = useMemo(
    () => (!selectedService ? allServicesTrendData(data?.scans ?? []) : []),
    [data, selectedService]
  );

  const chartConfig: ChartConfig = useMemo(() => {
    if (selectedService) {
      return {
        count: {
          label: `${selectedService} Vulnerabilities`,
          color:
            SERVICE_LIST.findIndex((s) => s === selectedService) >= 0
              ? SERVICE_COLORS[
                  SERVICE_LIST.findIndex((s) => s === selectedService) %
                    SERVICE_COLORS.length
                ]
              : "var(--color-count)",
        },
      };
    }

    const config: ChartConfig = {};
    SERVICE_LIST.forEach((service, idx) => {
      config[service] = {
        label: service,
        color: SERVICE_COLORS[idx % SERVICE_COLORS.length],
      };
    });
    return config;
  }, [selectedService]);

  const allZero = selectedService ? trend.every((d) => d.count === 0) : false;
  const hasNoData = !data || data.scans.length === 0;

  const latestIssuesCount = useMemo(() => {
    if (hasNoData) return 0;
    if (selectedService) {
      return trend[trend.length - 1]?.count || 0;
    }

    const latest = allServicesTrend[allServicesTrend.length - 1];
    if (!latest) return 0;
    return SERVICE_LIST.reduce(
      (sum, service) => sum + (latest[service] || 0),
      0
    );
  }, [hasNoData, selectedService, trend, allServicesTrend]);

  const peakCount = useMemo(() => {
    if (selectedService) {
      return Math.max(...trend.map((d) => d.count), 0);
    }

    return Math.max(
      ...allServicesTrend.map((scan) =>
        SERVICE_LIST.reduce((sum, service) => sum + (scan[service] || 0), 0)
      ),
      0
    );
  }, [selectedService, trend, allServicesTrend]);

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
                  Latest {selectedService || "All Services"} Issues
                </div>
                <div className="text-2xl font-bold">{latestIssuesCount}</div>
              </div>
              <div className="p-4 bg-muted rounded-lg">
                <div className="text-sm text-muted-foreground">Peak Count</div>
                <div className="text-2xl font-bold">{peakCount}</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="flex flex-col md:flex-row md:items-center md:justify-between">
          <CardTitle>AWS Vulnerability History</CardTitle>
          <Select value={selectedService} onValueChange={setSelectedService}>
            <SelectTrigger className="w-48">
              <SelectValue placeholder="All Services" />
            </SelectTrigger>
            <SelectContent>
              <Button
                className="w-full px-2"
                variant="secondary"
                size="sm"
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedService(undefined);
                }}
              >
                Show All Services
              </Button>
              <SelectSeparator />
              {SERVICE_LIST.map((svc) => (
                <SelectItem key={svc} value={svc}>
                  {svc}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center">
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
              <ChartContainer
                config={chartConfig}
                className="min-h-[280px] w-full"
              >
                <LineChart
                  data={selectedService ? trend : allServicesTrend}
                  margin={{ top: 5, right: 10, left: 10, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="date"
                    angle={-45}
                    textAnchor="end"
                    height={80}
                    tick={{ fontSize: 12 }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis
                    allowDecimals={false}
                    tickLine={false}
                    axisLine={false}
                  />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  {selectedService ? (
                    <Line
                      type="monotone"
                      dataKey="count"
                      stroke={
                        SERVICE_LIST.findIndex((s) => s === selectedService) >=
                        0
                          ? SERVICE_COLORS[
                              SERVICE_LIST.findIndex(
                                (s) => s === selectedService
                              ) % SERVICE_COLORS.length
                            ]
                          : "var(--color-count)"
                      }
                      strokeWidth={2}
                      dot={{
                        fill:
                          SERVICE_LIST.findIndex(
                            (s) => s === selectedService
                          ) >= 0
                            ? SERVICE_COLORS[
                                SERVICE_LIST.findIndex(
                                  (s) => s === selectedService
                                ) % SERVICE_COLORS.length
                              ]
                            : "var(--color-count)",
                        r: 4,
                      }}
                      activeDot={{ r: 6 }}
                    />
                  ) : (
                    SERVICE_LIST.map((service) => (
                      <Line
                        key={service}
                        type="monotone"
                        dataKey={service}
                        stroke={`var(--color-${service})`}
                        strokeWidth={2}
                        dot={{ r: 3 }}
                        activeDot={{ r: 5 }}
                      />
                    ))
                  )}
                </LineChart>
              </ChartContainer>
            )}
          </div>
        </CardContent>
      </Card>

      {!hasNoData && (
        <Card>
          <CardHeader>
            <CardTitle>All Scans</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scan Date</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-center">No. of Checks</TableHead>
                  <TableHead className="text-center">Total Findings</TableHead>
                  <TableHead className="text-center">High</TableHead>
                  <TableHead className="text-center">Medium</TableHead>
                  <TableHead className="text-center">Low</TableHead>
                  <TableHead className="text-center">Duration</TableHead>
                  <TableHead className="text-center">View Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.scans
                  .slice()
                  .sort((a, b) => {
                    const dateA = new Date(a.created_at).getTime();
                    const dateB = new Date(b.created_at).getTime();
                    return dateB - dateA;
                  })
                  .map((scan) => {
                    const createdDate = new Date(scan.created_at);
                    const completedDate = scan.completed_at
                      ? new Date(scan.completed_at)
                      : null;
                    const duration = completedDate
                      ? Math.round(
                          (completedDate.getTime() - createdDate.getTime()) /
                            1000
                        )
                      : null;

                    return (
                      <TableRow key={scan.scan_id}>
                        <TableCell className="font-medium">
                          {createdDate.toLocaleString("en-US", {
                            month: "short",
                            day: "numeric",
                            year: "numeric",
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              scan.completed_at ? "default" : "secondary"
                            }
                          >
                            {scan.completed_at ? "Completed" : "In Progress"}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-semibold text-center">
                          {scan.selected_scans.flat().length} Checks (
                          {scan.selected_scans.length} Services)
                        </TableCell>
                        <TableCell className="text-center font-semibold">
                          {scan.findings?.length || 0}
                        </TableCell>
                        <TableCell className="text-center">
                          <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-red-100 text-red-700 text-sm font-medium">
                            {getSeverityCount(scan.findings || [], "High")}
                          </span>
                        </TableCell>
                        <TableCell className="text-center">
                          <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-yellow-100 text-yellow-700 text-sm font-medium">
                            {getSeverityCount(scan.findings || [], "Medium")}
                          </span>
                        </TableCell>
                        <TableCell className="text-center">
                          <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-green-100 text-green-700 text-sm font-medium">
                            {getSeverityCount(scan.findings || [], "Low")}
                          </span>
                        </TableCell>
                        <TableCell className="text-center">
                          {duration ? `${duration}s` : `-`}
                        </TableCell>
                        <TableCell className="text-center">
                          <Link
                            to="/scans/$scanId"
                            params={{ scanId: scan.scan_id }}
                            target="_blank"
                            className="flex items-center justify-center underline text-sky-300 gap-2"
                          >
                            Visit
                            <ArrowUpRight className="size-4" />
                          </Link>
                        </TableCell>
                      </TableRow>
                    );
                  })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
