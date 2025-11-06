import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Download,
  FileText,
  Database,
  FileSpreadsheet,
  Loader2,
} from "lucide-react";
import { useAWSStore } from "@/lib/aws-store";
import { useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api-client";

interface ReportsTabProps {
  scanId: string;
  scanType?: "service" | "file";
}

interface GenerateReportResponse {
  report_url: string;
}

export function ReportsTab({ scanId, scanType = "service" }: ReportsTabProps) {
  const { credentials } = useAWSStore();
  const [downloading, setDownloading] = useState<string | null>(null);

  const generateServiceUrl = api.useMutation("post", "/api/generate-report");
  const generateFileUrl = api.useMutation(
    "post",
    "/api/generate-file-report" as any
  );

  const downloadReport = async (format: "csv" | "json" | "pdf") => {
    if (!credentials) {
      toast.error("No credentials available");
      return;
    }

    setDownloading(format);
    try {
      const mutation =
        scanType === "file" ? generateFileUrl : generateServiceUrl;

      const response = await mutation.mutateAsync({
        body: {
          scan_id: scanId,
          format: format,
        },
      } as any);

      // Type assertion to extract the report URL
      const reportData = response as unknown as GenerateReportResponse;
      const { report_url } = reportData;

      // Fetch the report with credentials
      const headers = new Headers();
      headers.append("X-AWS-Access-Key", credentials.access_key);
      headers.append("X-AWS-Secret-Key", credentials.secret_key);
      headers.append("X-AWS-Region", credentials.region || "us-east-1");

      const reportResponse = await fetch(`http://localhost:5000${report_url}`, {
        headers,
      });

      if (!reportResponse.ok) {
        throw new Error(
          `HTTP ${reportResponse.status}: ${reportResponse.statusText}`
        );
      }

      const blob = await reportResponse.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `${scanType}-scan-report.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(downloadUrl);
      document.body.removeChild(a);

      toast.success(`${format.toUpperCase()} report downloaded successfully`);
    } catch (error) {
      console.error("Error generating report:", error);
      toast.error("Failed to generate or download report");
    } finally {
      setDownloading(null);
    }
  };

  const reportOptions = [
    {
      format: "pdf" as const,
      title: "PDF Report",
      description: "Comprehensive formatted report",
      icon: FileText,
    },
    {
      format: "json" as const,
      title: "JSON Export",
      description: "Machine-readable data format",
      icon: Database,
    },
    {
      format: "csv" as const,
      title: "CSV Export",
      description: "Spreadsheet-compatible format",
      icon: FileSpreadsheet,
    },
  ];

  return (
    <div className="space-y-4">
      <div className="text-sm text-slate-400">
        Generate {scanType} scan reports
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {reportOptions.map(({ format, title, description, icon: Icon }) => (
          <Card key={format} className="border-slate-800 bg-slate-900/50">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Icon className="h-5 w-5 text-cyan-400" />
                <CardTitle className="text-lg text-slate-100">
                  {title}
                </CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-slate-400">{description}</p>
              <Button
                onClick={() => downloadReport(format)}
                disabled={downloading !== null}
                className="w-full bg-linear-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold"
              >
                {downloading === format ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-pulse" />
                    Downloading...
                  </>
                ) : (
                  <>
                    <Download className="h-4 w-4 mr-2" />
                    Download {format.toUpperCase()}
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
