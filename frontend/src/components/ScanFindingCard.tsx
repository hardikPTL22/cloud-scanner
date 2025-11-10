import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Copy,
  ExternalLink,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { toast } from "sonner";

interface ScanFindingCardProps {
  finding: any;
  formatSize: (bytes?: number) => string;
}

export function ScanFindingCard({ finding, formatSize }: ScanFindingCardProps) {
  const [expandedEngines, setExpandedEngines] = useState(false);

  const isMalicious = finding.status === "Malicious";
  const isSuspicious = finding.status === "Suspicious";

  const toggleEngines = () => setExpandedEngines((prev) => !prev);

  return (
    <div
      className={`
    relative border-l-2 p-6 my-4 bg-black shadow-[0_0_0_1px_rgba(255,255,255,0.03)]
    ${
      isMalicious
        ? "border-red-500/80"
        : isSuspicious
        ? "border-amber-500/80"
        : "border-emerald-500/80"
    }
  `}
    >
      {/* HEADER */}
      <div className="grid grid-cols-2 gap-4 items-center">
        <div className="flex items-start gap-3 min-w-0">
          <div className="mt-0.5">
            {isMalicious || isSuspicious ? (
              <AlertTriangle
                className={`h-5 w-5 ${
                  isMalicious ? "text-red-500" : "text-amber-500"
                }`}
              />
            ) : (
              <CheckCircle2 className="h-5 w-5 text-emerald-500" />
            )}
          </div>

          <div className="flex flex-col min-w-0">
            <h3 className="font-semibold truncate">{finding.file_name}</h3>

            {finding.file_key !== finding.file_name && (
              <p className="text-xs text-muted-foreground truncate font-mono mt-0.5">
                {finding.file_key}
              </p>
            )}
          </div>
        </div>

        <div className="flex items-center justify-end gap-2">
          <Badge
            variant="outline"
            className={
              isMalicious
                ? "text-red-500 border-red-500/30"
                : isSuspicious
                ? "text-amber-500 border-amber-500/30"
                : "text-emerald-500 border-emerald-500/30"
            }
          >
            {finding.severity}
          </Badge>

          {finding.permalink && (
            <Button variant="ghost" size="sm" asChild>
              <a
                href={finding.permalink}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-sky-400 hover:text-sky-300"
              >
                VT
                <ExternalLink className="h-3 w-3" />
              </a>
            </Button>
          )}
        </div>
      </div>

      {/* STATS */}
      <div className="grid grid-cols-4 gap-8 py-4 mt-4 border-y border-neutral-900/80">
        <div className="text-center space-y-1">
          <div className="text-[11px] text-neutral-500 uppercase tracking-wide">
            Malicious
          </div>
          <div
            className={`text-2xl font-bold ${
              isMalicious
                ? "text-red-500"
                : isSuspicious
                ? "text-amber-500"
                : "text-emerald-500"
            }`}
          >
            {finding.malicious_count || 0}
          </div>
        </div>

        <div className="text-center space-y-1">
          <div className="text-[11px] text-neutral-500 uppercase tracking-wide">
            Suspicious
          </div>
          <div
            className={`text-2xl font-bold ${
              isSuspicious
                ? "text-amber-500"
                : isMalicious
                ? "text-red-500"
                : "text-emerald-500"
            }`}
          >
            {finding.suspicious_count || 0}
          </div>
        </div>

        <div className="text-center space-y-1">
          <div className="text-[11px] text-neutral-500 uppercase tracking-wide">
            Undetected
          </div>
          <div className="text-2xl font-bold text-neutral-400">
            {finding.undetected_count || 0}
          </div>
        </div>

        <div className="text-center space-y-1">
          <div className="text-[11px] text-neutral-500 uppercase tracking-wide">
            Harmless
          </div>
          <div className="text-2xl font-bold text-emerald-500">
            {finding.harmless_count || 0}
          </div>
        </div>
      </div>

      {/* COLLAPSIBLE detected engines */}
      {finding.detected_engines && finding.detected_engines.length > 0 && (
        <div className="mt-3 space-y-2">
          <button
            onClick={toggleEngines}
            className="text-xs font-medium text-sky-400 hover:text-sky-300 flex items-center gap-1"
          >
            Detected by {finding.detected_engines.length} engines
            {expandedEngines ? (
              <ChevronUp className="h-3 w-3" />
            ) : (
              <ChevronDown className="h-3 w-3" />
            )}
          </button>

          {expandedEngines && (
            <div className="flex flex-wrap gap-2">
              {finding.detected_engines.map((engine: string, i: number) => (
                <Badge key={i} variant="secondary">
                  {engine}
                </Badge>
              ))}
            </div>
          )}
        </div>
      )}

      {/* FILE DETAILS */}
      <div className="grid grid-cols-2 gap-3 text-sm mt-4 pb-4 border-b border-neutral-900/80">
        <div className="space-y-1">
          <div className="text-xs text-neutral-500 uppercase tracking-wide">
            Type
          </div>
          <div className="font-mono">{finding.file_type || "Unknown"}</div>
        </div>
        <div className="space-y-1">
          <div className="text-xs text-neutral-500 uppercase tracking-wide">
            Size
          </div>
          <div className="font-mono">{formatSize(finding.file_size)}</div>
        </div>

        {finding.sha256 && (
          <div className="pt-4 space-y-1">
            <div className="flex items-center justify-between">
              <div className="text-xs text-neutral-500 uppercase tracking-wide">
                SHA256 Hash
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  navigator.clipboard.writeText(finding.sha256);
                  toast.success("Hash copied!");
                }}
              >
                <Copy className="h-3 w-3" />
              </Button>
            </div>
            <div className="font-mono text-xs text-neutral-400 break-all">
              {finding.sha256}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
