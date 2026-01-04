import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { client } from "@/lib/api-client";
import { buildCompliance } from "@/lib/grc-utils";

import ComplianceOverview from "@/components/grc/ComplianceOverview";
import FrameworkScoreCards from "@/components/grc/FrameworkScoreCards";
import NonCompliantControls from "@/components/grc/NonCompliantControls";
import ComplianceTrendChart from "@/components/grc/ComplianceTrendChart";

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
            compliance: compliance.compliance_percentage,
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

  const compliance = buildCompliance(latestScanQuery.data ?? []);

  return (
    <div className="space-y-6">
      <ComplianceOverview summary={compliance} />

      <ComplianceTrendChart data={trendQuery.data ?? []} />

      <FrameworkScoreCards frameworks={compliance.frameworks} />

      <NonCompliantControls
        controls={compliance.frameworks[0].controls.filter(
          (c) => c.status === "non-compliant"
        )}
      />
    </div>
  );
}
