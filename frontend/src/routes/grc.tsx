import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { client } from "@/lib/api-client";
import { buildCompliance } from "@/lib/grc-utils";
import type { GRCDashboardResponse } from "@/types/grc";
import ComplianceOverview from "@/components/grc/ComplianceOverview";
import FrameworkScoreCards from "@/components/grc/FrameworkScoreCards";
import NonCompliantControls from "@/components/grc/NonCompliantControls";
import ComplianceTrendChart from "@/components/grc/ComplianceTrendChart";
import RiskHeatmap from "@/components/grc/RiskHeatmap";

export const Route = createFileRoute("/grc")({
  component: GRCPage,
});

function GRCPage() {
  const scansQuery = useQuery({
    queryKey: ["scans"],
    queryFn: async () => {
      const res = await client.GET("/api/scans");
      return res.data?.scans ?? [];
    },
  });

  const scans = scansQuery.data ?? [];
  const latestScanId = scans[0]?.scan_id;

  const latestScanQuery = useQuery({
    enabled: !!latestScanId,
    queryKey: ["latest-scan", latestScanId],
    queryFn: async () => {
      const res = await client.GET("/api/scans/{scan_id}", {
        params: { path: { scan_id: latestScanId! } },
      });
      return res.data?.findings ?? [];
    },
  });

  const trendQuery = useQuery({
    enabled: scans.length > 0,
    queryKey: ["grc-trend"],
    queryFn: async () => {
      const points = await Promise.all(
        scans.map(async (scan) => {
          const res = await client.GET("/api/scans/{scan_id}", {
            params: { path: { scan_id: scan.scan_id } },
          });

          const findings = res.data?.findings ?? [];
          const compliance = buildCompliance(findings);

          return {
            date: new Date(scan.created_at).toLocaleDateString(),
            compliance: compliance.overall_compliance,
          };
        })
      );

      return points.reverse();
    },
  });

  if (
    scansQuery.isLoading ||
    latestScanQuery.isLoading ||
    trendQuery.isLoading
  ) {
    return <div>Loading GRC dashboard...</div>;
  }

  if (!latestScanId) {
    return <div>No scans found. Run a scan first.</div>;
  }

  const findings = latestScanQuery.data ?? [];
  const complianceSummary = buildCompliance(findings);

  const mockGRCData: GRCDashboardResponse = {
    compliance_summary: complianceSummary,
    control_effectiveness: null,
    non_compliant_controls: [],
    risk_distribution: {
      critical: findings.filter((f) => f.severity?.toLowerCase() === "critical")
        .length,
      high: findings.filter((f) => f.severity?.toLowerCase() === "high").length,
      medium: findings.filter((f) => f.severity?.toLowerCase() === "medium")
        .length,
      low: findings.filter((f) => f.severity?.toLowerCase() === "low").length,
      informational: 0,
    },
    total_risk_score: findings.length * 5,
    average_risk_score: 5.0,
    findings_count: findings.length,
    controls_failed: findings.filter(
      (f) => f.severity?.toLowerCase() === "high"
    ).length,
  };

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">GRC Dashboard</h1>

      <ComplianceOverview data={mockGRCData} />

      <FrameworkScoreCards
        compliance={complianceSummary}
        effectiveness={null}
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <ComplianceTrendChart data={trendQuery.data ?? []} />
        </div>
        <div>
          <RiskHeatmap data={mockGRCData} />
        </div>
      </div>

      <div className="space-y-4">
        <h2 className="text-2xl font-bold">Non-Compliant Controls</h2>
        <NonCompliantControls controls={mockGRCData.non_compliant_controls} />
      </div>
    </div>
  );
}
