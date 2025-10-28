import { useAWSStore } from "@/lib/aws-store";
import { CredentialsCard } from "@/components/credentials-card";
import { useNavigate } from "@tanstack/react-router";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/")({
  component: Page,
});

function Page() {
  const credentials = useAWSStore((state) => state.credentials);
  const navigate = useNavigate();

  if (credentials) {
    navigate({ to: "/scan" });
    return null;
  }

  return (
    <div className="min-h-screen bg-background">
      <CredentialsCard />
    </div>
  );
}
