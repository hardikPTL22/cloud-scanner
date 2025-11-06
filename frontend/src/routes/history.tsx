import { createFileRoute, Link } from "@tanstack/react-router";
import { useState, useMemo } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
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
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api-client";
import { RESOURCES_MAP } from "@/lib/resource-map";
import { ArrowUpRight, Filter, FileText, Cloud } from "lucide-react";

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
];

function countFindingsByService(scan: any, service: string) {
  if (!scan.findings) return 0;
  return scan.findings.filter(
    (f: any) => (SERVICE_MAP[f.type] || "OTHER") === service
  ).length;
}

function serviceTrendData(scans: any[]) {
  if (!scans || scans.length === 0) return [];

  const serviceScans = scans.filter((scan) => scan.scan_type === "service");

  return serviceScans
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

function fileTrendData(scans: any[]) {
  if (!scans || scans.length === 0) return [];

  const fileScans = scans.filter((scan) => scan.scan_type === "file");

  return fileScans
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
        malicious:
          scan.findings?.filter((f: any) => f.status === "Malicious").length ||
          0,
        suspicious:
          scan.findings?.filter((f: any) => f.status === "Suspicious").length ||
          0,
        clean:
          scan.findings?.filter((f: any) => f.status === "Clean").length || 0,
      };
    });
}

function getSeverityCount(findings: any[], severity: string) {
  if (!findings) return 0;
  return findings.filter((f) => f.severity === severity).length;
}

function getMaliciousCount(findings: any[]) {
  if (!findings) return 0;
  return findings.filter((f) => f.status === "Malicious").length;
}

function extractServices(selectedScans: any): string[] {
  if (!selectedScans || !Array.isArray(selectedScans)) {
    return [];
  }

  const services = new Set<string>();

  (selectedScans as string[]).forEach((item: string) => {
    if (typeof item === "string") {
      const service = SERVICE_MAP[item.toLowerCase()];
      if (service) {
        services.add(service.toUpperCase());
      } else {
        services.add(item.toUpperCase());
      }
    }
  });

  return Array.from(services).sort();
}

export const Route = createFileRoute("/history")({
  component: Page,
});

export function Page() {
  const { data, isLoading } = api.useQuery("get", "/api/scans");
  const [selectedServices, setSelectedServices] =
    useState<string[]>(SERVICE_LIST);
  const [scanTypeTab, setScanTypeTab] = useState<"service" | "file">("service");

  const toggleService = (service: string) => {
    setSelectedServices((prev) =>
      prev.includes(service)
        ? prev.filter((s) => s !== service)
        : [...prev, service]
    );
  };

  const selectAll = () => {
    setSelectedServices(SERVICE_LIST);
  };

  const clearAll = () => {
    setSelectedServices([]);
  };

  const filteredScans = useMemo(() => {
    if (!data?.scans) return [];
    if (scanTypeTab === "service") {
      return data.scans.filter((s: any) => s.scan_type === "service");
    } else if (scanTypeTab === "file") {
      return data.scans.filter((s: any) => s.scan_type === "file");
    }
    return data.scans;
  }, [data, scanTypeTab]);

  const serviceTrend = useMemo(
    () => serviceTrendData(data?.scans || []),
    [data]
  );
  const fileTrend = useMemo(() => fileTrendData(data?.scans || []), [data]);

  const hasNoData = !data || data.scans.length === 0;
  const hasNoFilteredData = filteredScans.length === 0;

  const serviceScanStats = useMemo(() => {
    const serviceScans = (data?.scans || []).filter(
      (s: any) => s.scan_type === "service"
    );
    return {
      total: serviceScans.length,
      totalFindings: serviceScans.reduce(
        (sum: number, s: any) => sum + (s.findings?.length || 0),
        0
      ),
    };
  }, [data]);

  const fileScanStats = useMemo(() => {
    const fileScans = (data?.scans || []).filter(
      (s: any) => s.scan_type === "file"
    );
    return {
      total: fileScans.length,
      totalFiles: fileScans.reduce(
        (sum: number, s: any) => sum + (s.metadata?.file_count || 0),
        0
      ),
      totalMalicious: fileScans.reduce(
        (sum: number, s: any) => sum + getMaliciousCount(s.findings || []),
        0
      ),
    };
  }, [data]);

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
      <Tabs
        value={scanTypeTab}
        onValueChange={(v) => setScanTypeTab(v as "service" | "file")}
        className="w-full"
      >
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="service">
            <Cloud className="h-4 w-4 mr-2" />
            Cloud Services
            <Badge variant="outline" className="ml-2">
              {serviceScanStats.total}
            </Badge>
          </TabsTrigger>
          <TabsTrigger value="file">
            <FileText className="h-4 w-4 mr-2" />
            File Scans
            <Badge variant="outline" className="ml-2">
              {fileScanStats.total}
            </Badge>
          </TabsTrigger>
        </TabsList>

        {scanTypeTab === "service" && !hasNoFilteredData && (
          <>
            <Card className="mt-6">
              <CardHeader>
                <CardTitle>Summary</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  <div className="p-4 bg-muted rounded-lg">
                    <div className="text-sm text-muted-foreground">
                      Service Scans
                    </div>
                    <div className="text-2xl font-bold">
                      {serviceScanStats.total}
                    </div>
                  </div>
                  <div className="p-4 bg-muted rounded-lg">
                    <div className="text-sm text-muted-foreground">
                      Total Findings
                    </div>
                    <div className="text-2xl font-bold">
                      {serviceScanStats.totalFindings}
                    </div>
                  </div>
                  <div className="p-4 bg-muted rounded-lg">
                    <Popover>
                      <PopoverTrigger asChild>
                        <Button variant="outline" className="w-full">
                          <Filter className="h-4 w-4 mr-2" />
                          {selectedServices.length === SERVICE_LIST.length
                            ? "All Services"
                            : `${selectedServices.length} Selected`}
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-64 p-4" align="end">
                        <div className="space-y-4">
                          <div className="flex items-center justify-between">
                            <h4 className="font-semibold text-sm">
                              Filter Services
                            </h4>
                            <div className="flex gap-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={selectAll}
                                className="h-7 text-xs"
                              >
                                All
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={clearAll}
                                className="h-7 text-xs"
                              >
                                Clear
                              </Button>
                            </div>
                          </div>
                          <div className="space-y-3 max-h-80 overflow-y-auto">
                            {SERVICE_LIST.map((service, idx) => (
                              <div
                                key={service}
                                className="flex items-center space-x-2"
                              >
                                <Checkbox
                                  id={service}
                                  checked={selectedServices.includes(service)}
                                  onCheckedChange={() => toggleService(service)}
                                />
                                <Label
                                  htmlFor={service}
                                  className="text-sm font-normal cursor-pointer flex items-center gap-2"
                                >
                                  <div
                                    className="w-3 h-3 rounded-full"
                                    style={{
                                      backgroundColor:
                                        SERVICE_COLORS[
                                          idx % SERVICE_COLORS.length
                                        ],
                                    }}
                                  />
                                  {service}
                                </Label>
                              </div>
                            ))}
                          </div>
                        </div>
                      </PopoverContent>
                    </Popover>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Vulnerability Trend</CardTitle>
              </CardHeader>
              <CardContent>
                {serviceTrend.length === 0 ? (
                  <div className="flex items-center justify-center h-96 text-muted-foreground">
                    No service scan data available
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={650}>
                    <LineChart
                      data={serviceTrend}
                      margin={{ top: 5, right: 30, left: 0, bottom: 80 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis
                        dataKey="date"
                        angle={-45}
                        textAnchor="end"
                        height={80}
                        tick={{ fontSize: 11 }}
                      />
                      <YAxis />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "#1f2937",
                          border: "1px solid #374151",
                          borderRadius: "6px",
                          color: "#e5e7eb",
                        }}
                        labelStyle={{ color: "#e5e7eb" }}
                        itemStyle={{ color: "#e5e7eb" }}
                      />
                      <Legend
                        wrapperStyle={{ fontSize: "11px", paddingTop: "15px" }}
                      />
                      {selectedServices.map((service, idx) => (
                        <Line
                          key={service}
                          type="monotone"
                          dataKey={service}
                          stroke={SERVICE_COLORS[idx % SERVICE_COLORS.length]}
                          strokeWidth={2}
                          dot={false}
                        />
                      ))}
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>

            <Card className="mt-6">
              <CardHeader>
                <CardTitle>Cloud Service Scans</CardTitle>
              </CardHeader>
              <CardContent className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Scan Date</TableHead>
                      <TableHead>Services Selected</TableHead>
                      <TableHead>Total Checks</TableHead>
                      <TableHead>Findings</TableHead>
                      <TableHead className="text-center">Critical</TableHead>
                      <TableHead className="text-center">High</TableHead>
                      <TableHead className="text-center">Medium</TableHead>
                      <TableHead>View</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredScans
                      .slice()
                      .sort(
                        (a: any, b: any) =>
                          new Date(b.created_at).getTime() -
                          new Date(a.created_at).getTime()
                      )
                      .map((scan: any) => {
                        const servicesSelected = extractServices(
                          scan.selected_scans
                        );
                        const totalChecks = scan.metadata?.total_checks || 0;
                        const criticalCount = getSeverityCount(
                          scan.findings || [],
                          "Critical"
                        );
                        const highCount = getSeverityCount(
                          scan.findings || [],
                          "High"
                        );
                        const mediumCount = getSeverityCount(
                          scan.findings || [],
                          "Medium"
                        );

                        return (
                          <TableRow key={scan.scan_id}>
                            <TableCell className="whitespace-nowrap">
                              {new Date(scan.created_at).toLocaleString()}
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-wrap gap-1">
                                {servicesSelected.length > 0 ? (
                                  servicesSelected.map((service: string) => (
                                    <Badge
                                      key={`${scan.scan_id}-${service}`}
                                      className="text-xs text-white font-semibold"
                                      style={{
                                        backgroundColor:
                                          SERVICE_COLORS[
                                            SERVICE_LIST.indexOf(service) %
                                              SERVICE_COLORS.length
                                          ],
                                        opacity: 0.9,
                                      }}
                                    >
                                      {service}
                                    </Badge>
                                  ))
                                ) : (
                                  <span className="text-muted-foreground text-sm">
                                    -
                                  </span>
                                )}
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <Badge
                                  variant="outline"
                                  className="font-semibold"
                                >
                                  {totalChecks}
                                </Badge>
                                <span className="text-xs text-muted-foreground">
                                  {servicesSelected.length > 0
                                    ? `(${servicesSelected.length} services)`
                                    : ""}
                                </span>
                              </div>
                            </TableCell>
                            <TableCell className="text-center font-semibold">
                              {scan.findings?.length || 0}
                            </TableCell>
                            <TableCell className="text-center">
                              <Badge variant="destructive">
                                {criticalCount}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-center">
                              <Badge variant="destructive">{highCount}</Badge>
                            </TableCell>
                            <TableCell className="text-center">
                              <Badge variant="secondary">{mediumCount}</Badge>
                            </TableCell>
                            <TableCell className="text-center">
                              <Link
                                to="/scans/$scanId"
                                params={{ scanId: scan.scan_id }}
                                className="text-sky-400 hover:text-sky-300"
                              >
                                <ArrowUpRight className="h-4 w-4" />
                              </Link>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </>
        )}

        {scanTypeTab === "file" && !hasNoFilteredData && (
          <>
            <Card className="mt-6">
              <CardHeader>
                <CardTitle>Summary</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="p-4 bg-muted rounded-lg">
                    <div className="text-sm text-muted-foreground">
                      File Scans
                    </div>
                    <div className="text-2xl font-bold">
                      {fileScanStats.total}
                    </div>
                  </div>
                  <div className="p-4 bg-muted rounded-lg">
                    <div className="text-sm text-muted-foreground">
                      Files Scanned
                    </div>
                    <div className="text-2xl font-bold">
                      {fileScanStats.totalFiles}
                    </div>
                  </div>
                  <div className="p-4 bg-muted rounded-lg">
                    <div className="text-sm text-muted-foreground">
                      Malicious
                    </div>
                    <div className="text-2xl font-bold text-red-600">
                      {fileScanStats.totalMalicious}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>File Scan Trend</CardTitle>
              </CardHeader>
              <CardContent>
                {fileTrend.length === 0 ? (
                  <div className="flex items-center justify-center h-96 text-muted-foreground">
                    No file scan data
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={650}>
                    <LineChart
                      data={fileTrend}
                      margin={{ top: 5, right: 30, left: 0, bottom: 80 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis
                        dataKey="date"
                        angle={-45}
                        textAnchor="end"
                        height={80}
                        tick={{ fontSize: 11 }}
                      />
                      <YAxis />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "#1f2937",
                          border: "1px solid #374151",
                          borderRadius: "6px",
                          color: "#e5e7eb",
                        }}
                        labelStyle={{ color: "#e5e7eb" }}
                        itemStyle={{ color: "#e5e7eb" }}
                      />
                      <Legend
                        wrapperStyle={{ fontSize: "11px", paddingTop: "15px" }}
                      />
                      <Line
                        type="monotone"
                        dataKey="malicious"
                        stroke="#dc2626"
                        strokeWidth={2}
                        dot={false}
                        name="Malicious"
                      />
                      <Line
                        type="monotone"
                        dataKey="suspicious"
                        stroke="#f59e0b"
                        strokeWidth={2}
                        dot={false}
                        name="Suspicious"
                      />
                      <Line
                        type="monotone"
                        dataKey="clean"
                        stroke="#10b981"
                        strokeWidth={2}
                        dot={false}
                        name="Clean"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>

            <Card className="mt-6">
              <CardHeader>
                <CardTitle>File Scans</CardTitle>
              </CardHeader>
              <CardContent className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Scan Date</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-center">
                        Files Scanned
                      </TableHead>
                      <TableHead className="text-center">Malicious</TableHead>
                      <TableHead className="text-center">Suspicious</TableHead>
                      <TableHead className="text-center">Clean</TableHead>
                      <TableHead className="text-center">View</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredScans
                      .slice()
                      .sort(
                        (a: any, b: any) =>
                          new Date(b.created_at).getTime() -
                          new Date(a.created_at).getTime()
                      )
                      .map((scan: any) => (
                        <TableRow key={scan.scan_id}>
                          <TableCell className="whitespace-nowrap">
                            {new Date(scan.created_at).toLocaleString()}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="secondary"
                              className="bg-slate-700 text-slate-100 dark:bg-slate-700 dark:text-slate-100"
                            >
                              📁 File
                            </Badge>
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
                          <TableCell className="text-center font-semibold">
                            {scan.metadata?.file_count || 0}
                          </TableCell>
                          <TableCell className="text-center font-semibold text-red-600">
                            {getMaliciousCount(scan.findings || [])}
                          </TableCell>
                          <TableCell className="text-center font-semibold text-yellow-500">
                            {
                              (scan.findings || []).filter(
                                (f: any) => f.status === "Suspicious"
                              ).length
                            }
                          </TableCell>
                          <TableCell className="text-center font-semibold text-green-500">
                            {
                              (scan.findings || []).filter(
                                (f: any) => f.status === "Clean"
                              ).length
                            }
                          </TableCell>
                          <TableCell className="text-center">
                            <Link
                              to="/scans/$scanId"
                              params={{ scanId: scan.scan_id }}
                              className="text-sky-400 hover:text-sky-300"
                            >
                              <ArrowUpRight className="h-4 w-4" />
                            </Link>
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </>
        )}

        {hasNoData && (
          <Card className="mt-6">
            <CardContent className="flex items-center justify-center h-72">
              <div className="text-muted-foreground text-center">
                <p className="mb-2">No scan history available yet.</p>
                <p className="text-sm">
                  Run your first scan to see results here.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {hasNoFilteredData && !hasNoData && (
          <Card className="mt-6">
            <CardContent className="flex items-center justify-center h-72">
              <div className="text-muted-foreground">
                No {scanTypeTab} scans found.
              </div>
            </CardContent>
          </Card>
        )}
      </Tabs>
    </div>
  );
}
