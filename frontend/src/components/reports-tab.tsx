import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Download, FileText, Database, FileSpreadsheet, Loader2 } from 'lucide-react';
import { useAWSStore } from '@/store/aws-store';
import { apiService } from '@/services/api';
import type { Finding } from '@/types';
import { useState } from 'react';
import { toast } from 'sonner';

interface ReportsTabProps {
    findings: Finding[];
}

export function ReportsTab({ findings }: ReportsTabProps) {
    const { credentials } = useAWSStore();
    const [downloading, setDownloading] = useState<string | null>(null);

    const downloadReport = async (format: 'csv' | 'json' | 'pdf') => {
        if (!credentials || findings.length === 0) {
            toast.error(findings.length === 0 ? 'No findings to export' : 'No credentials available');
            return;
        }

        setDownloading(format);
        try {
            const blob = await apiService.downloadReport(credentials, findings, format);

            // Create download link
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security-report.${format}`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            toast.success(`${format.toUpperCase()} report downloaded successfully`);
        } catch (error) {
            console.error('Download failed', error);
            toast.error('Download Failed');
        } finally {
            setDownloading(null);
        }
    };

    const reportOptions = [
        {
            format: 'pdf' as const,
            title: 'PDF Report',
            description: 'Comprehensive formatted report',
            icon: FileText,
        },
        {
            format: 'json' as const,
            title: 'JSON Export',
            description: 'Machine-readable data format',
            icon: Database,
        },
        {
            format: 'csv' as const,
            title: 'CSV Export',
            description: 'Spreadsheet-compatible format',
            icon: FileSpreadsheet,
        },
    ];

    return (
        <div className="space-y-4">
            <div className="text-sm text-muted-foreground">
                {findings.length > 0
                    ? `Generate reports from ${findings.length} findings`
                    : 'Run a scan first to generate reports'
                }
            </div>

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
                                disabled={findings.length === 0 || downloading !== null}
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