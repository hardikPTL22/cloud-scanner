import { client } from "@/lib/api-client";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FindingsTable } from "@/components/findings-table";
import { ReportsTab } from "@/components/reports-tab";
import { ScanCharts } from "@/components/scan-charts";

export const Route = createFileRoute("/scans/$scanId")({
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
      throw new Error("Failed to load scan details");
    }

    return data;
  },
});

function Page() {
  const { scanId } = Route.useParams();
  const { findings } = Route.useLoaderData();
  const navigate = useNavigate();

  console.log("Findings:", findings);

  if (!findings) {
    navigate({ to: "/history" });
    toast.info("No findings found for this scan.");
    return null;
  }

  return (
    <>
      <div>
        <h1 className="text-2xl font-bold mb-4">Scan Details</h1>
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
              <CardTitle>Security Findings</CardTitle>
            </CardHeader>
            <CardContent>
              <FindingsTable findings={findings} />
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
