import type { NonCompliantControl } from "@/types/grc";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

export default function NonCompliantControls({
  controls,
}: {
  controls: NonCompliantControl[];
}) {
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  const toggleRow = (controlId: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(controlId)) {
        next.delete(controlId);
      } else {
        next.add(controlId);
      }
      return next;
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-purple-600 hover:bg-purple-700";
      case "high":
        return "bg-red-600 hover:bg-red-700";
      case "medium":
        return "bg-yellow-600 hover:bg-yellow-700";
      case "low":
        return "bg-blue-600 hover:bg-blue-700";
      default:
        return "bg-gray-600 hover:bg-gray-700";
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 9) return "text-purple-600 font-bold";
    if (score >= 7) return "text-red-600 font-bold";
    if (score >= 4) return "text-yellow-600 font-bold";
    return "text-blue-600 font-bold";
  };

  if (!controls.length) {
    return (
      <div className="text-muted-foreground text-sm">
        No non-compliant controls found.
      </div>
    );
  }

  return (
    <div className="border rounded-lg">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-12"></TableHead>
            <TableHead>Control ID</TableHead>
            <TableHead>Framework</TableHead>
            <TableHead>Title</TableHead>
            <TableHead>Service</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Risk Score</TableHead>
            <TableHead>Findings</TableHead>
          </TableRow>
        </TableHeader>

        <TableBody>
          {controls.map((control) => {
            const isExpanded = expandedRows.has(control.control_id);
            return (
              <>
                <TableRow
                  key={control.control_id}
                  className="cursor-pointer"
                  onClick={() => toggleRow(control.control_id)}
                >
                  <TableCell>
                    <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                    </Button>
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {control.control_id}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">
                      {control.framework.toUpperCase()}
                    </Badge>
                  </TableCell>
                  <TableCell>{control.title}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">
                      {control.service.toUpperCase()}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge className={getSeverityColor(control.severity)}>
                      {control.severity.toUpperCase()}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span className={getRiskColor(control.risk_score.score)}>
                      {control.risk_score.score.toFixed(1)}
                    </span>
                    <span className="text-xs text-muted-foreground ml-1">
                      / 10
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{control.finding_count}</Badge>
                  </TableCell>
                </TableRow>

                {isExpanded && (
                  <TableRow>
                    <TableCell colSpan={8} className="bg-muted/50">
                      <div className="p-4 space-y-4">
                        <div>
                          <h4 className="font-semibold text-sm mb-2">
                            Risk Analysis
                          </h4>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                            <div>
                              <span className="text-muted-foreground">
                                CVSS Base:
                              </span>
                              <span className="ml-2 font-medium">
                                {control.risk_score.cvss_base}
                              </span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">
                                Impact Factor:
                              </span>
                              <span className="ml-2 font-medium">
                                {control.risk_score.impact_factor}x
                              </span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">
                                Exploitability:
                              </span>
                              <span className="ml-2 font-medium">
                                {control.risk_score.exploitability_factor}x
                              </span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">
                                Risk Level:
                              </span>
                              <Badge
                                className={`ml-2 ${getSeverityColor(
                                  control.risk_score.level
                                )}`}
                              >
                                {control.risk_score.level.toUpperCase()}
                              </Badge>
                            </div>
                          </div>
                        </div>

                        <div>
                          <h4 className="font-semibold text-sm mb-2">
                            Finding Types ({control.finding_types.length})
                          </h4>
                          <div className="flex flex-wrap gap-2">
                            {control.finding_types.map(
                              (type: string, idx: number) => (
                                <Badge
                                  key={idx}
                                  variant="outline"
                                  className="font-mono text-xs"
                                >
                                  {type}
                                </Badge>
                              )
                            )}
                          </div>
                        </div>

                        <div>
                          <h4 className="font-semibold text-sm mb-2">
                            Affected Resources ({control.resource_ids.length})
                          </h4>
                          <div className="max-h-32 overflow-y-auto">
                            <div className="space-y-1">
                              {control.resource_ids.map(
                                (resource: string, idx: number) => (
                                  <div
                                    key={idx}
                                    className="text-xs font-mono bg-background p-2 rounded border"
                                  >
                                    {resource}
                                  </div>
                                )
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
