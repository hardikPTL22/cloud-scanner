import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAWSStore } from "@/lib/aws-store";
import type { AWSCredentials } from "@/types";
import { toast } from "sonner";
import { Loader2 } from "lucide-react";
import { useNavigate } from "@tanstack/react-router";
import { api } from "@/lib/api-client";

export function CredentialsCard() {
  const credentials = useAWSStore((state) => state.credentials);
  const [formData, setFormData] = useState<AWSCredentials>({
    access_key: credentials?.access_key ?? "",
    secret_key: credentials?.secret_key ?? "",
    region: credentials?.region ?? "us-east-1",
  });
  const setCredentials = useAWSStore((state) => state.setCredentials);
  const clearCredentials = useAWSStore((state) => state.clearCredentials);
  const validate = api.useMutation("post", "/api/validate");
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (formData.access_key && formData.secret_key && formData.region) {
        const { valid } = await validate.mutateAsync({
          body: {
            access_key: formData.access_key,
            secret_key: formData.secret_key,
            region: formData.region,
          },
        });
        if (valid) {
          setCredentials(formData);
          navigate({ to: "/scan" });
        } else {
          clearCredentials();
          toast.error("Invalid AWS Credentials.");
        }
      }
    } catch (error) {
      console.error("Could not validate AWS Credentials", error);
      toast.error("Could not validate AWS Credentials.");
    }
  };

  const handleInputChange =
    (field: keyof AWSCredentials) =>
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setFormData((prev) => ({ ...prev, [field]: e.target.value }));
    };

  return (
    <Card className="min-w-md w-fit mx-auto">
      <CardHeader>
        <CardTitle>AWS Credentials</CardTitle>
      </CardHeader>
      <CardContent className="sm:max-w-md">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="accessKey">Access Key</Label>
            <Input
              id="accessKey"
              type="text"
              value={formData.access_key}
              onChange={handleInputChange("access_key")}
              placeholder="AKIA..."
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="secretKey">Secret Key</Label>
            <Input
              id="secretKey"
              type="password"
              value={formData.secret_key}
              onChange={handleInputChange("secret_key")}
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
              onChange={handleInputChange("region")}
              placeholder="us-east-1"
              required
            />
          </div>
          <Button
            type="submit"
            className="w-full"
            disabled={validate.isPending}
          >
            {validate.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Validating Credentials...
              </>
            ) : (
              "Save Credentials"
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
