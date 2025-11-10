import { client } from "@/lib/api-client";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ReportsTab } from "@/components/reports-tab";
import { ScanCharts } from "@/components/scan-charts";
import { ScanFindingCard } from "@/components/ScanFindingCard";

export const Route = createFileRoute("/scans/file/$scanId")({
  component: Page,
  loader: async ({ params }) => {
    const { data, error } = await client.GET("/api/scans/{scan_id}", {
      params: {
        path: {
          scan_id: params.scanId,
        },
      },
    });

    if (error) {
      throw new Error("Failed to load file scan details");
    }

    return data;
  },
});

function formatSize(bytes?: number) {
  if (!bytes) return "-";
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

function Page() {
  const { scanId } = Route.useParams();
  const { findings } = Route.useLoaderData();
  const navigate = useNavigate();

  if (!findings) {
    navigate({ to: "/history" });
    toast.info("No findings found for this file scan.");
    return null;
  }

  return (
    <>
      <div>
        <h1 className="text-2xl font-bold mb-4">File Scan Details</h1>
      </div>
      <ScanCharts findings={findings} />
      <Tabs defaultValue="findings" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="findings">
            Scan Results ({findings.length})
          </TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
        </TabsList>
        <TabsContent value="findings" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Scan Results</CardTitle>
            </CardHeader>
            <CardContent>
              {findings.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <h3 className="text-xl font-semibold mb-2">All Clean</h3>
                  <p className="text-muted-foreground max-w-md">
                    No malicious files or threats were detected during the scan.
                    Your storage appears to be secure.
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {findings.map((finding: any) => (
                    <ScanFindingCard
                      key={finding.sha256}
                      finding={finding}
                      formatSize={formatSize}
                    />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="reports" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Download Reports</CardTitle>
            </CardHeader>
            <CardContent>
              <ReportsTab scanId={scanId} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  );
}
