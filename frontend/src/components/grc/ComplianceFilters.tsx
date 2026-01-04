import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";

type Props = {
  frameworks: string[];
  severities: string[];
  selectedFrameworks: string[];
  selectedSeverities: string[];
  onFrameworkChange: (fw: string) => void;
  onSeverityChange: (sev: string) => void;
};

export default function ComplianceFilters({
  frameworks,
  severities,
  selectedFrameworks,
  selectedSeverities,
  onFrameworkChange,
  onSeverityChange,
}: Props) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Compliance Filters</CardTitle>
      </CardHeader>

      <CardContent className="space-y-6">
        {/* Framework filter */}
        <div className="space-y-2">
          <Label className="font-semibold">Frameworks</Label>
          {frameworks.map((fw) => (
            <div key={fw} className="flex items-center space-x-2">
              <Checkbox
                checked={selectedFrameworks.includes(fw)}
                onCheckedChange={() => onFrameworkChange(fw)}
                id={`fw-${fw}`}
              />
              <Label htmlFor={`fw-${fw}`}>{fw.toUpperCase()}</Label>
            </div>
          ))}
        </div>

        {/* Severity filter */}
        <div className="space-y-2">
          <Label className="font-semibold">Severity</Label>
          {severities.map((sev) => (
            <div key={sev} className="flex items-center space-x-2">
              <Checkbox
                checked={selectedSeverities.includes(sev)}
                onCheckedChange={() => onSeverityChange(sev)}
                id={`sev-${sev}`}
              />
              <Label htmlFor={`sev-${sev}`}>{sev}</Label>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
