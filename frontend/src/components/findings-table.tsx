import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import type { Finding } from "@/types";

interface FindingsTableProps {
  findings: Finding[];
}

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case "High":
      return "destructive";
    case "Medium":
      return "default";
    case "Low":
      return "secondary";
    default:
      return "default";
  }
};

export function FindingsTable({ findings }: FindingsTableProps) {
  if (findings.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No findings to display
      </div>
    );
  }

  return (
    <div className="border rounded-lg text-left">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Type</TableHead>
            <TableHead>Name</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Details</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.map((finding, index) => (
            <TableRow key={index}>
              <TableCell className="font-medium">{finding.type}</TableCell>
              <TableCell>{finding.name}</TableCell>
              <TableCell>
                <Badge variant={getSeverityColor(finding.severity)}>
                  {finding.severity}
                </Badge>
              </TableCell>
              <TableCell className="max-w-md">{finding.details}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
