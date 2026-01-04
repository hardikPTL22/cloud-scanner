"use client";

import * as React from "react";
import { useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Pie,
  PieChart,
  Sector,
  Label,
} from "recharts";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  type ChartConfig,
  ChartContainer,
  ChartStyle,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
} from "@/components/ui/chart";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { RESOURCES_MAP } from "@/lib/resource-map";
import type { Finding } from "@/types";
import type { PieSectorDataItem } from "recharts/types/polar/Pie";

const SERVICE_MAP: Record<string, string> = {};
Object.entries(RESOURCES_MAP).forEach(([service, vulnerabilities]) => {
  vulnerabilities.forEach((vuln) => {
    SERVICE_MAP[vuln] = service.toUpperCase();
  });
});

const SERVICE_LIST = Object.keys(RESOURCES_MAP).map((s) => s.toUpperCase());

interface ScanChartsProps {
  findings: Finding[] | any[];
}

export function ScanCharts({ findings }: ScanChartsProps) {
  const isFileFindings = findings.length > 0 && findings[0]?.status;

  // ----- File Scan Results -----
  if (isFileFindings) {
    const maliciousCount = findings.filter(
      (f) => f.status === "Malicious"
    ).length;
    const suspiciousCount = findings.filter(
      (f) => f.status === "Suspicious"
    ).length;
    const cleanCount = findings.filter((f) => f.status === "Clean").length;

    const chartData = [
      { name: "Malicious", value: maliciousCount, fill: "#dc2626" },
      { name: "Suspicious", value: suspiciousCount, fill: "#f59e0b" },
      { name: "Clean", value: cleanCount, fill: "#10b981" },
    ];

    const chartConfig = {
      value: { label: "Files" },
      malicious: { label: "Malicious", color: "#dc2626" },
      suspicious: { label: "Suspicious", color: "#f59e0b" },
      clean: { label: "Clean", color: "#10b981" },
    } satisfies ChartConfig;

    const id = "scan-pie-chart";
    const [activeStatus, setActiveStatus] = React.useState("Malicious");
    const [hoveredIndex, setHoveredIndex] = React.useState<number | null>(null);

    const activeIndex = React.useMemo(
      () => chartData.findIndex((item) => item.name === activeStatus),
      [activeStatus]
    );
    const statuses = React.useMemo(
      () => chartData.map((item) => item.name),
      []
    );

    if (findings.length === 0) {
      return (
        <Card className="dark:border-slate-700 dark:bg-slate-950">
          <CardHeader>
            <CardTitle>File Scan Results</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-muted-foreground text-center py-8">
              No files detected in this scan.
            </div>
          </CardContent>
        </Card>
      );
    }

    return (
      <Card
        data-chart={id}
        className="flex flex-col dark:bg-slate-950 dark:border-slate-700"
      >
        <ChartStyle id={id} config={chartConfig} />
        <CardHeader className="flex-row items-start space-y-0 pb-0">
          <div className="grid gap-1">
            <CardTitle>File Scan Results</CardTitle>
            <CardDescription>{findings.length} files scanned</CardDescription>
          </div>
          <Select value={activeStatus} onValueChange={setActiveStatus}>
            <SelectTrigger
              className="ml-auto h-7 w-[130px] rounded-lg pl-2.5 dark:bg-slate-900 dark:border-slate-700"
              aria-label="Select status"
            >
              <SelectValue placeholder="Select status" />
            </SelectTrigger>
            <SelectContent align="end" className="rounded-xl dark:bg-slate-900">
              {statuses.map((status) => (
                <SelectItem
                  key={status}
                  value={status}
                  className="rounded-lg [&_span]:flex"
                >
                  <div className="flex items-center gap-2 text-xs">
                    <span
                      className="flex h-3 w-3 shrink-0 rounded-xs"
                      style={{
                        backgroundColor:
                          status === "Malicious"
                            ? "#dc2626"
                            : status === "Suspicious"
                            ? "#f59e0b"
                            : "#10b981",
                      }}
                    />
                    {status}
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent className="flex flex-1 justify-center pb-0">
          <ChartContainer
            id={id}
            config={chartConfig}
            className="mx-auto aspect-square w-full max-w-[400px]"
          >
            <PieChart>
              <ChartTooltip
                cursor={false}
                content={<ChartTooltipContent hideLabel />}
              />
              <Pie
                data={chartData}
                dataKey="value"
                nameKey="name"
                innerRadius={60}
                outerRadius={100}
                strokeWidth={5}
                activeIndex={hoveredIndex !== null ? hoveredIndex : activeIndex}
                onMouseEnter={(_, index) => setHoveredIndex(index)}
                onMouseLeave={() => setHoveredIndex(null)}
                activeShape={({
                  outerRadius = 0,
                  ...props
                }: PieSectorDataItem) => (
                  <g>
                    <Sector {...props} outerRadius={outerRadius + 10} />
                    <Sector
                      {...props}
                      outerRadius={outerRadius + 25}
                      innerRadius={outerRadius + 12}
                    />
                  </g>
                )}
              >
                <Label
                  content={({ viewBox }) => {
                    if (viewBox && "cx" in viewBox && "cy" in viewBox) {
                      const selectedData = chartData[activeIndex];
                      return (
                        <text
                          x={viewBox.cx}
                          y={viewBox.cy}
                          textAnchor="middle"
                          dominantBaseline="middle"
                        >
                          <tspan
                            x={viewBox.cx}
                            y={viewBox.cy}
                            className="fill-slate-100 dark:fill-slate-100 text-3xl font-bold"
                          >
                            {selectedData.value}
                          </tspan>
                          <tspan
                            x={viewBox.cx}
                            y={(viewBox.cy || 0) + 24}
                            className="fill-slate-400 dark:fill-slate-400"
                          >
                            {selectedData.name} Files
                          </tspan>
                        </text>
                      );
                    }
                  }}
                />
              </Pie>
            </PieChart>
          </ChartContainer>
        </CardContent>
      </Card>
    );
  }

  // ---- VULNERABILITY CHARTS ----

  // --- 1. Bar & Radar Data: Only show services with findings ---
  const chartData = useMemo(() => {
    const serviceData: Record<
      string,
      {
        service: string;
        High: number;
        Medium: number;
        Low: number;
        total: number;
      }
    > = {};

    SERVICE_LIST.forEach((service) => {
      serviceData[service] = {
        service,
        High: 0,
        Medium: 0,
        Low: 0,
        total: 0,
      };
    });

    findings.forEach((finding) => {
      const service = SERVICE_MAP[finding.type] || "OTHER";
      if (serviceData[service]) {
        serviceData[service][finding.severity as "High" | "Medium" | "Low"]++;
        serviceData[service].total++;
      }
    });

    // Show only services with at least one finding
    return Object.values(serviceData).filter((data) => data.total > 0);
  }, [findings]);

  // --- 2. Radar chart data ---
  const radarData = useMemo(
    () =>
      chartData.map((data) => ({
        service: data.service,
        vulnerabilities: data.total,
      })),
    [chartData]
  );

  // --- 3. PIE CHART DATA ---

  const pieChartConfig: ChartConfig = {
    high: {
      label: "High",
      color: "#ef4444",
    },
    medium: {
      label: "Medium",
      color: "#f59e0b",
    },
    low: {
      label: "Low",
      color: "#22c55e",
    },
  };

  const pieChartData = useMemo(() => {
    const severityCounts: Record<string, number> = {
      High: 0,
      Medium: 0,
      Low: 0,
    };

    findings.forEach((finding) => {
      if (severityCounts[finding.severity] !== undefined) {
        severityCounts[finding.severity]++;
      }
    });

    return Object.entries(severityCounts).map(([severity, count]) => ({
      severity,
      count,
      fill: pieChartConfig[severity.toLowerCase()]?.color || "",
    }));
  }, [findings]);

  if (chartData.length === 0) {
    return (
      <Card className="dark:border-slate-700 dark:bg-slate-950">
        <CardHeader>
          <CardTitle>Vulnerability Analysis</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-muted-foreground text-center py-8">
            No vulnerabilities detected in this scan.
          </div>
        </CardContent>
      </Card>
    );
  }

  // --- Bar/Radar Chart Config ---
  const barChartConfig: ChartConfig = {
    High: { label: "High", color: "#ef4444" },
    Medium: { label: "Medium", color: "#f59e0b" },
    Low: { label: "Low", color: "#22c55e" },
  };

  const radarChartConfig: ChartConfig = {
    vulnerabilities: { label: "Vulnerabilities", color: "#6366f1" },
  };

  return (
    <div className="grid gap-6 md:grid-cols-2">
      {/* Bar chart: Severity by Service */}
      <Card className="md:col-span-2 dark:border-slate-700 dark:bg-slate-950">
        <CardHeader>
          <CardTitle>Severity Distribution by Service</CardTitle>
        </CardHeader>
        <CardContent>
          <ChartContainer
            config={barChartConfig}
            className="min-h-[300px] w-full"
          >
            <BarChart
              data={chartData}
              margin={{ top: 5, right: 10, left: 10, bottom: 50 }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis
                dataKey="service"
                angle={-45}
                textAnchor="end"
                height={80}
                tick={{ fontSize: 12 }}
                tickLine={false}
                axisLine={false}
              />
              <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
              <ChartTooltip content={<ChartTooltipContent />} />
              <ChartLegend content={<ChartLegendContent />} />
              <Bar
                dataKey="High"
                fill="var(--color-High)"
                radius={[4, 4, 0, 0]}
              />
              <Bar
                dataKey="Medium"
                fill="var(--color-Medium)"
                radius={[4, 4, 0, 0]}
              />
              <Bar
                dataKey="Low"
                fill="var(--color-Low)"
                radius={[4, 4, 0, 0]}
              />
            </BarChart>
          </ChartContainer>
        </CardContent>
      </Card>
      {/* Radar chart */}
      <Card className="dark:border-slate-700 dark:bg-slate-950">
        <CardHeader>
          <CardTitle>Vulnerability Distribution by Service</CardTitle>
        </CardHeader>
        <CardContent>
          <ChartContainer
            config={radarChartConfig}
            className="min-h-[300px] w-full"
          >
            <RadarChart data={radarData}>
              <ChartTooltip content={<ChartTooltipContent />} cursor={false} />
              <PolarGrid gridType="polygon" />
              <PolarAngleAxis dataKey="service" tick={{ fontSize: 12 }} />
              <PolarRadiusAxis
                angle={90}
                domain={[0, "dataMax"]}
                tickCount={5}
                tick={{ fontSize: 10 }}
              />
              <Radar
                name="Vulnerabilities"
                dataKey="vulnerabilities"
                stroke="var(--color-vulnerabilities)"
                fill="var(--color-vulnerabilities)"
                fillOpacity={0.6}
                dot={{
                  r: 4,
                  fill: "var(--color-vulnerabilities)",
                }}
              />
            </RadarChart>
          </ChartContainer>
        </CardContent>
      </Card>
      {/* Pie chart */}
      <Card className="dark:border-slate-700 dark:bg-slate-950">
        <CardHeader>
          <CardTitle>Severity Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <ChartContainer
            config={pieChartConfig}
            className="min-h-[300px] w-full"
          >
            <PieChart>
              <ChartTooltip
                cursor={false}
                content={<ChartTooltipContent hideLabel />}
              />
              <Pie
                data={pieChartData}
                dataKey="count"
                nameKey="severity"
                innerRadius={60}
                strokeWidth={5}
                activeIndex={0}
                activeShape={({
                  outerRadius = 0,
                  ...props
                }: PieSectorDataItem) => (
                  <Sector {...props} outerRadius={outerRadius + 10} />
                )}
              />
            </PieChart>
          </ChartContainer>
        </CardContent>
      </Card>
    </div>
  );
}
