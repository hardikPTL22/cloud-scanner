import { createRootRoute, Outlet, useRouter } from "@tanstack/react-router";
import { Separator } from "@/components/ui/separator";
import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Toaster } from "@/components/ui/sonner";
import { useAWSStore } from "@/lib/aws-store";
import { Link } from "@tanstack/react-router";

function RootLayout() {
  const { clearCredentials } = useAWSStore();
  const router = useRouter();

  const handleLogout = () => {
    clearCredentials();
    router.navigate({ to: "/" });
  };

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-primary" />
            <h1 className="text-2xl font-bold">AWS Security Scanner</h1>
          </div>
          <div className="flex items-center gap-4">
            <Button asChild variant="ghost" size="sm">
              <Link to="/scan">Scan</Link>
            </Button>
            <Button asChild variant="ghost" size="sm">
              <Link to="/history">History</Link>
            </Button>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleLogout}>
              Logout
            </Button>
          </div>
        </div>

        <Separator />
        <Outlet />

        <Toaster richColors />
      </div>
    </div>
  );
}

export const Route = createRootRoute({ component: RootLayout });
