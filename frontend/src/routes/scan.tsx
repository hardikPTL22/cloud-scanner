import { createFileRoute } from "@tanstack/react-router";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAWSStore } from "@/lib/aws-store";
import type { Finding } from "@/types";
import { FindingsTable } from "@/components/findings-table";
import { ReportsTab } from "@/components/reports-tab";
import { ServiceSelector } from "@/components/service-selector";
import { toast } from "sonner";
import { Loader2 } from "lucide-react";
import { api } from "@/lib/api-client";

export const Route = createFileRoute("/scan")({
  component: Page,
});

function Page() {
  const { credentials } = useAWSStore();
  const [selectedServices, setSelectedServices] = useState<
    Record<string, string[]>
  >({});
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanId, setScanId] = useState<string | null>(null);
  const scan = api.useMutation("post", "/api/scan");

  const handleScan = async () => {
    if (!credentials || Object.keys(selectedServices).length === 0) {
      toast.error(
        Object.keys(selectedServices).length === 0
          ? "Please select at least one service to scan"
          : "No credentials available"
      );
      return;
    }
    try {
      const { findings, scan_id } = await scan.mutateAsync({
        body: {
          services: selectedServices,
        },
      });
      if (findings) {
        setFindings(findings);
        setScanId(scan_id);
        toast.success("Scan Complete", {
          description: `Found ${findings.length} findings`,
        });
      } else {
        toast.success("No vulnerabilities found");
      }
    } catch (error) {
      toast.error("Scan Failed", {
        description: error instanceof Error ? error.message : "Unknown error",
      });
    }
  };
  return (
    <>
      <ServiceSelector
        selectedServices={selectedServices}
        onSelectionChange={setSelectedServices}
      />

      <div className="flex justify-center">
        <Button
          onClick={handleScan}
          disabled={
            scan.isPending || Object.keys(selectedServices).length === 0
          }
          size="lg"
          className="px-8"
        >
          {scan.isPending ? (
            <>
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              Scanning...
            </>
          ) : (
            "Start Security Scan"
          )}
        </Button>
      </div>

      {scanId && findings.length > 0 && (
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
      )}
    </>
  );
}
