import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAWSStore } from '@/store/aws-store';
import type { AWSCredentials } from '@/types';
import { toast } from 'sonner';
import { apiService } from '@/services/api';
import { Loader2 } from 'lucide-react';

interface CredentialsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CredentialsDialog({ open, onOpenChange }: CredentialsDialogProps) {
  const credentials = useAWSStore((state) => state.credentials);
  const [formData, setFormData] = useState<AWSCredentials>({
    accessKey: credentials?.accessKey ?? '',
    secretKey: credentials?.secretKey ?? '',
    region: credentials?.region ?? '',
  });
  const setCredentials = useAWSStore((state) => state.setCredentials);
  const [validating, setValidating] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setValidating(true);
      if (formData.accessKey && formData.secretKey && formData.region) {
        const res = await apiService.validateCredentials({ accessKey: formData.accessKey, secretKey: formData.secretKey, region: formData.region })
        if (res) {
          setCredentials(formData);
          onOpenChange(false);
        } else {
          toast.error('Invalid AWS Credentials.');
        }
      }
    } catch (error) {
      console.error('Could not validate AWS Credentials', error);
      toast.error('Could not validate AWS Credentials.');
    } finally {
      setValidating(false);
    }
  };

  const handleInputChange = (field: keyof AWSCredentials) => (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    setFormData((prev) => ({ ...prev, [field]: e.target.value }));
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>AWS Credentials</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="accessKey">Access Key</Label>
            <Input
              id="accessKey"
              type="text"
              value={formData.accessKey}
              onChange={handleInputChange('accessKey')}
              placeholder="AKIA..."
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="secretKey">Secret Key</Label>
            <Input
              id="secretKey"
              type="password"
              value={formData.secretKey}
              onChange={handleInputChange('secretKey')}
              placeholder="Enter secret key"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="region">Region</Label>
            <Input
              id="region"
              type="text"
              value={formData.region}
              onChange={handleInputChange('region')}
              placeholder="us-east-1"
              required
            />
          </div>
          <Button type="submit" className="w-full" disabled={validating}>
            {validating ? <>
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              Validating Credentials...
            </> : "Save Credentials"}
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}