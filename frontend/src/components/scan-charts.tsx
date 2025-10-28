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
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  type ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
} from "@/components/ui/chart";
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
  findings: Finding[];
}

export function ScanCharts({ findings }: ScanChartsProps) {
  // Group findings by service and severity
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

    // Initialize all services with zero counts
    SERVICE_LIST.forEach((service) => {
      serviceData[service] = {
        service,
        High: 0,
        Medium: 0,
        Low: 0,
        total: 0,
      };
    });

    // Count findings by service and severity
    findings.forEach((finding) => {
      const service = SERVICE_MAP[finding.type] || "OTHER";
      if (serviceData[service]) {
        serviceData[service][finding.severity as "High" | "Medium" | "Low"]++;
        serviceData[service].total++;
      }
    });

    return Object.values(serviceData).filter((data) => data.total > 0);
  }, [findings]);

  const radarData = useMemo(() => {
    return chartData.map((data) => ({
      service: data.service,
      vulnerabilities: data.total,
    }));
  }, [chartData]);

  const barChartConfig: ChartConfig = {
    High: {
      label: "High",
      color: "#ef4444",
    },
    Medium: {
      label: "Medium",
      color: "#f59e0b",
    },
    Low: {
      label: "Low",
      color: "#22c55e",
    },
  };

  const radarChartConfig: ChartConfig = {
    vulnerabilities: {
      label: "Vulnerabilities",
      color: "#6366f1",
    },
  };

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

    findings.reduce((acc, finding) => {
      acc[finding.severity] = (acc[finding.severity] || 0) + 1;
      return acc;
    }, severityCounts);

    return Object.entries(severityCounts).map(([severity, count]) => ({
      severity,
      count,
      fill: pieChartConfig[severity.toLowerCase()]?.color || "",
    }));
  }, []);

  if (chartData.length === 0) {
    return (
      <Card>
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

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card className="md:col-span-2">
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

      <Card>
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

      <Card>
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
