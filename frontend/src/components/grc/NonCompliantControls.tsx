import type { ControlItem } from "@/lib/grc-types";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

export default function NonCompliantControls({
  controls,
}: {
  controls: ControlItem[];
}) {
  if (!controls.length) {
    return (
      <div className="text-muted-foreground text-sm">
        No non-compliant controls found.
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>ISO</TableHead>
          <TableHead>Title</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Service</TableHead>
          <TableHead>Status</TableHead>
        </TableRow>
      </TableHeader>

      <TableBody>
        {controls.map((c, idx) => (
          <TableRow key={idx}>
            <TableCell>{c.iso ?? c.id}</TableCell>
            <TableCell>{c.title}</TableCell>
            <TableCell>
              <Badge variant="destructive">{c.severity}</Badge>
            </TableCell>
            <TableCell>{c.service}</TableCell>
            <TableCell>
              <Badge variant="destructive">Non-Compliant</Badge>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
