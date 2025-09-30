import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Loader2, Settings, Shield } from "lucide-react";
import { useAWSStore } from "@/store/aws-store";
import { apiService } from "@/services/api";
import type { Finding } from "@/types";
import { FindingsTable } from "./findings-table";
import { ReportsTab } from "./reports-tab";
import { ServiceSelector } from "./service-selector";
import { CredentialsDialog } from "./credentials-dialog";
import { toast } from "sonner";

export function MainInterface() {
  const { credentials, clearCredentials } = useAWSStore();
  const [selectedServices, setSelectedServices] = useState<string[]>([]);
  const [scanning, setScanning] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [showCredentialsDialog, setShowCredentialsDialog] = useState(false);

  const handleScan = async () => {
    if (!credentials || selectedServices.length === 0) {
      toast.error(
        selectedServices.length === 0
          ? "Please select at least one service to scan"
          : "No credentials available"
      );
      return;
    }

    setScanning(true);
    try {
      const result = await apiService.scan(credentials, selectedServices);
      setFindings(result.findings);
      toast.success("Scan Complete", {
        description: `Found ${result.findings.length} findings`,
      });
    } catch (error) {
      toast.error("Scan Failed");
    } finally {
      setScanning(false);
    }
  };

  const handleLogout = () => {
    clearCredentials();
    setSelectedServices([]);
    setFindings([]);
  };

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-primary" />
            <h1 className="text-3xl font-bold">AWS Security Scanner</h1>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowCredentialsDialog(true)}
            >
              <Settings className="h-4 w-4 mr-2" />
              Settings
            </Button>
            <Button variant="outline" size="sm" onClick={handleLogout}>
              Logout
            </Button>
          </div>
        </div>

        <Separator />

        <ServiceSelector
          selectedServices={selectedServices}
          onSelectionChange={setSelectedServices}
        />

        <div className="flex justify-center">
          <Button
            onClick={handleScan}
            disabled={scanning || selectedServices.length === 0}
            size="lg"
            className="px-8"
          >
            {scanning ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Scanning...
              </>
            ) : (
              "Start Security Scan"
            )}
          </Button>
        </div>

        {findings.length > 0 && (
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
                  <ReportsTab findings={findings} />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        )}

        <CredentialsDialog
          open={showCredentialsDialog}
          onOpenChange={setShowCredentialsDialog}
        />
      </div>
    </div>
  );
}
