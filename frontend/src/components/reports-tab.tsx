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
}

export function ReportsTab({ scanId }: ReportsTabProps) {
  const { credentials } = useAWSStore();
  const [downloading, setDownloading] = useState<string | null>(null);
  const generateUrl = api.useMutation("post", "/api/generate-report");

  const downloadReport = (format: "csv" | "json" | "pdf") => {
    if (!credentials) {
      toast.error("No credentials available");
      return;
    }

    setDownloading(format);
    generateUrl
      .mutateAsync({
        body: {
          scan_id: scanId,
          format: format,
        },
      })
      .then(({ report_url }) => {
        window.open(`http://localhost:5000${report_url}`, "_blank")?.focus();
        toast.success(`${format.toUpperCase()} report downloaded successfully`);
      })
      .catch((error) => {
        console.error("Error generating report:", error);
        toast.error("Failed to generate report");
      })
      .finally(() => {
        setDownloading(null);
      });
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
      <div className="text-sm text-muted-foreground">Generate reports</div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {reportOptions.map(({ format, title, description, icon: Icon }) => (
          <Card key={format} className="relative">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Icon className="h-5 w-5 text-primary" />
                <CardTitle className="text-lg">{title}</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">{description}</p>
              <Button
                onClick={() => downloadReport(format)}
                disabled={downloading !== null}
                className="w-full"
                variant={downloading === format ? "secondary" : "default"}
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
