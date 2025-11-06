import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ReportsTab } from "@/components/reports-tab";
import { ScanCharts } from "@/components/scan-charts";
import { toast } from "sonner";
import {
  Loader2,
  Folder,
  File,
  ChevronRight,
  ChevronDown,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Copy,
  AlertCircle,
} from "lucide-react";
import { api } from "@/lib/api-client";
import { Input } from "@/components/ui/input";

interface FileItem {
  key: string;
  name: string;
  type: "file" | "folder";
  size?: number;
  lastModified?: string;
  children?: FileItem[];
  isExpanded?: boolean;
}

interface FileScanTabProps {
  onScanComplete: (findings: any[], scanId: string) => void;
  findings: any[];
  scanId: string | null;
}

interface StorageService {
  value: string;
  label: string;
  icon: string;
}

const FILE_STORAGE_SERVICES: StorageService[] = [
  {
    value: "s3",
    label: "S3 Buckets",
    icon: "/assets/Simple Storage Service.svg",
  },
  {
    value: "efs",
    label: "EFS File Systems",
    icon: "/assets/EFS.svg",
  },
  {
    value: "fsx",
    label: "FSx File Systems",
    icon: "/assets/FSx.svg",
  },
];

export function FileScanTab({
  onScanComplete,
  findings,
  scanId,
}: FileScanTabProps) {
  const [selectedService, setSelectedService] = useState<string>("");
  const [buckets, setBuckets] = useState<string[]>([]);
  const [selectedBucket, setSelectedBucket] = useState<string>("");
  const [files, setFiles] = useState<FileItem[]>([]);
  const [selectedFiles, setSelectedFiles] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState("");
  const [isLoadingBuckets, setIsLoadingBuckets] = useState(false);
  const [isLoadingFiles, setIsLoadingFiles] = useState(false);
  const [isScanning, setIsScanning] = useState(false);

  const fetchBuckets = api.useMutation("get", "/api/buckets" as any);
  const fetchFiles = api.useMutation("post", "/api/files/list" as any);
  const scanFiles = api.useMutation("post", "/api/files/scan" as any);

  useEffect(() => {
    if (selectedService === "s3") {
      handleFetchBuckets();
    } else {
      setBuckets([]);
      setSelectedBucket("");
      setFiles([]);
    }
  }, [selectedService]);

  useEffect(() => {
    if (selectedBucket && selectedService === "s3") {
      handleFetchFiles();
    } else {
      setFiles([]);
      setSelectedFiles(new Set());
    }
  }, [selectedBucket]);

  const handleFetchBuckets = async () => {
    setIsLoadingBuckets(true);
    try {
      const response: any = await fetchBuckets.mutateAsync({});
      if (response?.buckets) {
        setBuckets(response.buckets);
        toast.success(`Found ${response.buckets.length} buckets`);
      }
    } catch (error) {
      toast.error("Failed to fetch buckets", {
        description: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setIsLoadingBuckets(false);
    }
  };

  const handleFetchFiles = async () => {
    if (!selectedBucket) return;
    setIsLoadingFiles(true);
    try {
      const response: any = await fetchFiles.mutateAsync({
        body: {
          service: selectedService,
          location: selectedBucket,
        } as any,
      });
      if (response?.files) {
        setFiles(response.files);
        toast.success(`Loaded ${response.files.length} items`);
      }
    } catch (error) {
      toast.error("Failed to fetch files", {
        description: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setIsLoadingFiles(false);
    }
  };

  const handleScanFiles = async () => {
    if (selectedFiles.size === 0) {
      toast.error("Please select at least one file or folder to scan");
      return;
    }
    setIsScanning(true);
    try {
      const response: any = await scanFiles.mutateAsync({
        body: {
          service: selectedService,
          location: selectedBucket,
          files: Array.from(selectedFiles),
        } as any,
      });
      if (response?.findings) {
        onScanComplete(response.findings, response.scan_id);
        toast.success("File Scan Complete", {
          description: `Scanned ${response.findings.length} files`,
        });
      } else {
        toast.success("No vulnerabilities found in scanned files");
      }
    } catch (error) {
      toast.error("File Scan Failed", {
        description: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setIsScanning(false);
    }
  };

  const toggleFileSelection = (key: string, item: FileItem) => {
    const newSelected = new Set(selectedFiles);
    if (newSelected.has(key)) {
      newSelected.delete(key);
      if (item.type === "folder" && item.children) {
        const removeChildren = (children: FileItem[]) => {
          children.forEach((child) => {
            newSelected.delete(child.key);
            if (child.children) {
              removeChildren(child.children);
            }
          });
        };
        removeChildren(item.children);
      }
    } else {
      newSelected.add(key);
      if (item.type === "folder" && item.children) {
        const addChildren = (children: FileItem[]) => {
          children.forEach((child) => {
            newSelected.add(child.key);
            if (child.children) {
              addChildren(child.children);
            }
          });
        };
        addChildren(item.children);
      }
    }
    setSelectedFiles(newSelected);
  };

  const toggleFolder = (key: string) => {
    const toggleInTree = (items: FileItem[]): FileItem[] => {
      return items.map((item) => {
        if (item.key === key) {
          return { ...item, isExpanded: !item.isExpanded };
        }
        if (item.children) {
          return { ...item, children: toggleInTree(item.children) };
        }
        return item;
      });
    };
    setFiles(toggleInTree(files));
  };

  const selectAll = () => {
    const allKeys = new Set<string>();
    const collectKeys = (items: FileItem[]) => {
      items.forEach((item) => {
        allKeys.add(item.key);
        if (item.children) {
          collectKeys(item.children);
        }
      });
    };
    collectKeys(files);
    setSelectedFiles(allKeys);
  };

  const clearAll = () => {
    setSelectedFiles(new Set());
  };

  const filteredFiles = files.filter((file) =>
    file.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const formatSize = (bytes?: number) => {
    if (!bytes) return "-";
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
  };

  const renderFileTree = (items: FileItem[], depth = 0) => {
    return items.map((item) => (
      <div key={item.key}>
        <div
          className={`flex items-center gap-3 py-2 px-3 rounded-md transition-colors hover:bg-accent/50 ${
            selectedFiles.has(item.key) ? "bg-accent" : ""
          }`}
          style={{ paddingLeft: `${depth * 1.5 + 0.75}rem` }}
        >
          {item.type === "folder" && (
            <button
              onClick={() => toggleFolder(item.key)}
              className="p-0 hover:bg-transparent"
              aria-label={item.isExpanded ? "Collapse folder" : "Expand folder"}
            >
              {item.isExpanded ? (
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              ) : (
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              )}
            </button>
          )}
          {!item.type.includes("folder") && <div className="w-4" />}
          <Checkbox
            id={item.key}
            checked={selectedFiles.has(item.key)}
            onCheckedChange={() => toggleFileSelection(item.key, item)}
          />
          {item.type === "folder" ? (
            <Folder className="h-4 w-4 text-primary" />
          ) : (
            <File className="h-4 w-4 text-muted-foreground" />
          )}
          <Label
            htmlFor={item.key}
            className="flex-1 cursor-pointer font-medium text-sm"
          >
            {item.name}
          </Label>
          {item.type === "file" && (
            <span className="text-xs text-muted-foreground">
              {formatSize(item.size)}
            </span>
          )}
          {item.type === "folder" && item.children && (
            <Badge variant="secondary" className="text-xs">
              {item.children.length}
            </Badge>
          )}
        </div>
        {item.type === "folder" && item.isExpanded && item.children && (
          <div>{renderFileTree(item.children, depth + 1)}</div>
        )}
      </div>
    ));
  };

  const maliciousCount = findings.filter(
    (f: any) => f.status === "Malicious"
  ).length;
  const suspiciousCount = findings.filter(
    (f: any) => f.status === "Suspicious"
  ).length;
  const cleanCount = findings.filter((f: any) => f.status === "Clean").length;
  const totalMaliciousDetections = findings.reduce(
    (sum: number, f: any) => sum + (f.malicious_count || 0),
    0
  );

  const selectedServiceData = FILE_STORAGE_SERVICES.find(
    (s) => s.value === selectedService
  );

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>File & Folder Scanner</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Storage Service</Label>
              <Select
                value={selectedService}
                onValueChange={setSelectedService}
              >
                <SelectTrigger className="w-full">
                  <div className="flex items-center gap-2">
                    {selectedServiceData ? (
                      <>
                        <img
                          src={selectedServiceData.icon}
                          alt={selectedServiceData.label}
                          className="h-5 w-5 object-contain"
                          onError={(e) => {
                            (e.target as HTMLImageElement).style.display =
                              "none";
                          }}
                        />
                        <span>{selectedServiceData.label}</span>
                      </>
                    ) : (
                      <span className="text-muted-foreground">
                        Select service
                      </span>
                    )}
                  </div>
                </SelectTrigger>
                <SelectContent>
                  {FILE_STORAGE_SERVICES.map((service) => (
                    <SelectItem key={service.value} value={service.value}>
                      <div className="flex items-center gap-3">
                        <img
                          src={service.icon}
                          alt={service.label}
                          className="h-5 w-5 object-contain"
                          onError={(e) => {
                            (e.target as HTMLImageElement).style.display =
                              "none";
                          }}
                        />
                        <span>{service.label}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Select Bucket</Label>
              <Select
                value={selectedBucket}
                onValueChange={setSelectedBucket}
                disabled={
                  !selectedService || isLoadingBuckets || buckets.length === 0
                }
              >
                <SelectTrigger>
                  <SelectValue
                    placeholder={
                      isLoadingBuckets
                        ? "Loading buckets..."
                        : buckets.length === 0
                        ? "No buckets found"
                        : "Select bucket"
                    }
                  />
                </SelectTrigger>
                <SelectContent>
                  {buckets.map((bucket) => (
                    <SelectItem key={bucket} value={bucket}>
                      {bucket}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {isLoadingBuckets && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Fetching buckets...
                </div>
              )}
            </div>
          </div>

          {isLoadingFiles && (
            <div className="flex items-center justify-center gap-2 text-sm py-8">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span className="text-muted-foreground">
                Loading files and folders...
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {files.length > 0 && (
        <>
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg">Select Files to Scan</CardTitle>
                <div className="flex gap-2">
                  <Badge variant="outline">{selectedFiles.size} selected</Badge>
                  <Button variant="ghost" size="sm" onClick={selectAll}>
                    Select All
                  </Button>
                  <Button variant="ghost" size="sm" onClick={clearAll}>
                    Clear
                  </Button>
                  <Button variant="ghost" size="sm" onClick={handleFetchFiles}>
                    <RefreshCw className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <Input
                  placeholder="Search files and folders..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
                <div className="max-h-96 overflow-y-auto border rounded-lg p-4">
                  {filteredFiles.length > 0 ? (
                    renderFileTree(filteredFiles)
                  ) : (
                    <div className="text-center text-muted-foreground py-12">
                      <File className="h-8 w-8 mx-auto mb-3 opacity-50" />
                      <p>No files found matching "{searchQuery}"</p>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="flex justify-center">
            <Button
              onClick={handleScanFiles}
              disabled={selectedFiles.size === 0 || isScanning}
              size="lg"
            >
              {isScanning ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Scanning {selectedFiles.size} Items...
                </>
              ) : (
                <>Scan {selectedFiles.size} Selected Items</>
              )}
            </Button>
          </div>
        </>
      )}

      {scanId && findings.length > 0 && (
        <>
          {(maliciousCount > 0 || suspiciousCount > 0 || cleanCount > 0) && (
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  {maliciousCount > 0 ? (
                    <AlertCircle className="h-5 w-5 text-destructive" />
                  ) : suspiciousCount > 0 ? (
                    <AlertTriangle className="h-5 w-5 text-orange-500" />
                  ) : (
                    <CheckCircle2 className="h-5 w-5 text-green-500" />
                  )}
                  <CardTitle>
                    {maliciousCount > 0
                      ? "Threats Detected"
                      : suspiciousCount > 0
                      ? "Suspicious Files Found"
                      : "All Files Clean"}
                  </CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="p-4 border rounded-lg">
                    <div className="text-xs text-muted-foreground font-medium mb-1">
                      Malicious
                    </div>
                    <div className="text-2xl font-bold text-destructive">
                      {maliciousCount}
                    </div>
                  </div>
                  <div className="p-4 border rounded-lg">
                    <div className="text-xs text-muted-foreground font-medium mb-1">
                      Suspicious
                    </div>
                    <div className="text-2xl font-bold text-orange-500">
                      {suspiciousCount}
                    </div>
                  </div>
                  <div className="p-4 border rounded-lg">
                    <div className="text-xs text-muted-foreground font-medium mb-1">
                      Clean
                    </div>
                    <div className="text-2xl font-bold text-green-500">
                      {cleanCount}
                    </div>
                  </div>
                  <div className="p-4 border rounded-lg">
                    <div className="text-xs text-muted-foreground font-medium mb-1">
                      Total Detections
                    </div>
                    <div className="text-2xl font-bold">
                      {totalMaliciousDetections}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {findings.length > 0 && <ScanCharts findings={findings} />}

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
                      <CheckCircle2 className="h-12 w-12 text-green-500 mb-4" />
                      <h3 className="text-xl font-semibold mb-2">All Clean</h3>
                      <p className="text-muted-foreground max-w-md">
                        No malicious files or threats were detected during the
                        scan. Your storage appears to be secure.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {findings.map((finding: any, idx: number) => {
                        const isMalicious = finding.status === "Malicious";
                        const isSuspicious = finding.status === "Suspicious";

                        return (
                          <div
                            key={idx}
                            className={`rounded-lg border p-4 ${
                              isMalicious
                                ? "border-destructive/50 bg-destructive/5"
                                : isSuspicious
                                ? "border-orange-500/50 bg-orange-500/5"
                                : "border-green-500/50 bg-green-500/5"
                            }`}
                          >
                            <div className="space-y-4">
                              {/* Header */}
                              <div className="flex items-start justify-between gap-4">
                                <div className="flex items-start gap-3 flex-1 min-w-0">
                                  <div className="mt-0.5">
                                    {isMalicious || isSuspicious ? (
                                      <AlertTriangle
                                        className={`h-5 w-5 ${
                                          isMalicious
                                            ? "text-destructive"
                                            : "text-orange-500"
                                        }`}
                                      />
                                    ) : (
                                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                                    )}
                                  </div>
                                  <div className="flex-1 min-w-0">
                                    <h3 className="font-semibold truncate">
                                      {finding.file_name}
                                    </h3>
                                    <p className="text-xs text-muted-foreground truncate font-mono mt-1">
                                      {finding.file_key}
                                    </p>
                                  </div>
                                </div>

                                <div className="flex items-center gap-2">
                                  <Badge
                                    variant={
                                      isMalicious
                                        ? "destructive"
                                        : isSuspicious
                                        ? "secondary"
                                        : "outline"
                                    }
                                  >
                                    {finding.severity}
                                  </Badge>

                                  {finding.permalink && (
                                    <Button variant="outline" size="sm" asChild>
                                      <a
                                        href={finding.permalink}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center gap-1"
                                      >
                                        VirusTotal
                                        <ExternalLink className="h-3 w-3" />
                                      </a>
                                    </Button>
                                  )}
                                </div>
                              </div>

                              {/* Stats Grid */}
                              <div className="grid grid-cols-4 gap-3 p-3 bg-muted/50 rounded-md">
                                <div className="text-center">
                                  <div className="text-xs text-muted-foreground font-medium mb-1">
                                    Malicious
                                  </div>
                                  <div className="text-xl font-bold text-destructive">
                                    {finding.malicious_count || 0}
                                  </div>
                                </div>
                                <div className="text-center">
                                  <div className="text-xs text-muted-foreground font-medium mb-1">
                                    Suspicious
                                  </div>
                                  <div className="text-xl font-bold text-orange-500">
                                    {finding.suspicious_count || 0}
                                  </div>
                                </div>
                                <div className="text-center">
                                  <div className="text-xs text-muted-foreground font-medium mb-1">
                                    Undetected
                                  </div>
                                  <div className="text-xl font-bold text-muted-foreground">
                                    {finding.undetected_count || 0}
                                  </div>
                                </div>
                                <div className="text-center">
                                  <div className="text-xs text-muted-foreground font-medium mb-1">
                                    Harmless
                                  </div>
                                  <div className="text-xl font-bold text-green-500">
                                    {finding.harmless_count || 0}
                                  </div>
                                </div>
                              </div>

                              {/* Detected Engines */}
                              {finding.detected_engines &&
                                finding.detected_engines.length > 0 && (
                                  <div className="space-y-2">
                                    <div className="text-xs font-medium text-muted-foreground">
                                      Detected by{" "}
                                      {finding.detected_engines.length} engines
                                    </div>
                                    <div className="flex flex-wrap gap-2">
                                      {finding.detected_engines
                                        .slice(0, 10)
                                        .map((engine: string, i: number) => (
                                          <Badge key={i} variant="secondary">
                                            {engine}
                                          </Badge>
                                        ))}
                                      {finding.detected_engines.length > 10 && (
                                        <Badge variant="outline">
                                          +
                                          {finding.detected_engines.length - 10}{" "}
                                          more
                                        </Badge>
                                      )}
                                    </div>
                                  </div>
                                )}

                              {/* File Details */}
                              <div className="grid grid-cols-2 gap-3 text-sm">
                                <div className="space-y-1">
                                  <div className="text-xs text-muted-foreground">
                                    Type
                                  </div>
                                  <div className="font-mono">
                                    {finding.file_type || "Unknown"}
                                  </div>
                                </div>
                                <div className="space-y-1">
                                  <div className="text-xs text-muted-foreground">
                                    Size
                                  </div>
                                  <div className="font-mono">
                                    {formatSize(finding.file_size)}
                                  </div>
                                </div>
                                {finding.sha256 && (
                                  <div className="col-span-2 space-y-1">
                                    <div className="flex items-center justify-between">
                                      <div className="text-xs text-muted-foreground">
                                        SHA256 Hash
                                      </div>
                                      <Button
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => {
                                          navigator.clipboard.writeText(
                                            finding.sha256
                                          );
                                          toast.success("Hash copied!");
                                        }}
                                      >
                                        <Copy className="h-3 w-3" />
                                      </Button>
                                    </div>
                                    <div className="font-mono text-xs break-all">
                                      {finding.sha256}
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        );
                      })}
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
                  <ReportsTab scanId={scanId} scanType="file" />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  );
}
