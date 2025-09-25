import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { Loader2, Settings, Shield } from 'lucide-react';
import { useAWSStore } from '@/store/aws-store';
import { apiService } from '@/services/api';
import type { Finding } from '@/types';
import { FindingsTable } from './findings-table';
import { ReportsTab } from './reports-tab';
import { CredentialsDialog } from './credentials-dialog';
import { toast } from 'sonner';

export function MainInterface() {
  const { credentials, clearCredentials } = useAWSStore();
  const [buckets, setBuckets] = useState<string[]>([]);
  const [files, setFiles] = useState<string[]>([]);
  const [selectedBucket, setSelectedBucket] = useState<string>('');
  const [selectedFile, setSelectedFile] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [showCredentialsDialog, setShowCredentialsDialog] = useState(false);

  useEffect(() => {
    if (credentials) {
      loadBuckets();
    }
  }, [credentials]);

  useEffect(() => {
    if (selectedBucket && credentials) {
      loadFiles();
    } else {
      setFiles([]);
      setSelectedFile('');
    }
  }, [selectedBucket, credentials]);

  const loadBuckets = async () => {
    if (!credentials) return;
    
    setLoading(true);
    try {
      const bucketList = await apiService.getBuckets(credentials);
      setBuckets(bucketList);
    } catch (error) {
      console.error('Failed to load buckets', error);
      toast.error('Failed to load buckets');
    } finally {
      setLoading(false);
    }
  };

  const loadFiles = async () => {
    if (!credentials || !selectedBucket) return;
    
    setLoading(true);
    try {
      const fileList = await apiService.getFiles(credentials, selectedBucket);
      setFiles(fileList);
    } catch (error) {
      console.error('Failed to load files', error);
      toast.error('Failed to load files');
    } finally {
      setLoading(false);
    }
  };

  const handleScan = async () => {
    if (!credentials) return;
    
    setScanning(true);
    try {
      const result = await apiService.scan(
        credentials,
        selectedBucket || undefined,
        selectedFile || undefined
      );
      setFindings(result.findings);
      toast.success(`Found ${result.findings.length} findings`);
    } catch (error) {
      console.error('Scan failed', error);
      toast.error('Scan Failed');
    } finally {
      setScanning(false);
    }
  };

  const handleLogout = () => {
    clearCredentials();
    setBuckets([]);
    setFiles([]);
    setSelectedBucket('');
    setSelectedFile('');
    setFindings([]);
  };

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
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

        {/* Controls */}
        <Card>
          <CardHeader>
            <CardTitle>Scan Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex flex-col gap-y-2 items-start">
                <label className="text-sm font-medium">S3 Bucket</label>
                <Select
                  value={selectedBucket}
                  onValueChange={setSelectedBucket}
                  disabled={loading}
                >
                  <SelectTrigger className='w-full'>
                    <SelectValue placeholder="Select a bucket" />
                  </SelectTrigger>
                  <SelectContent>
                    {buckets.map((bucket) => (
                      <SelectItem key={bucket} value={bucket}>
                        {bucket}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex flex-col gap-y-2 items-start">
                <label className="text-sm font-medium">File (Optional)</label>
                <Select
                  value={selectedFile}
                  onValueChange={(value) => setSelectedFile(value === "none" ? "" : value)}
                  disabled={loading || !selectedBucket}
                >
                  <SelectTrigger className='w-full'>
                    <SelectValue placeholder="Select a file (optional)" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">No file selected</SelectItem>
                    {files.map((file) => (
                      <SelectItem key={file} value={file}>
                        {file}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <Button
              onClick={handleScan}
              disabled={scanning || loading}
              className="w-full md:w-auto"
            >
              {scanning ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Scanning...
                </>
              ) : (
                'Start Scan'
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Results Tabs */}
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