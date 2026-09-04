import { EmptyState, type FindingsTableRow, FindingsTable } from "@/src/lib/_bok-ui";

/**
 * Fixture-only route for exercising `FindingsTable` end to end (severity
 * glyphs, tabular numeric cells, provenance column) -- this is what
 * `tests/tokens.spec.ts` drives via `?fixture=mixed`. Task 11 replaces this
 * with the real screen wired to `src/lib/api.ts::getFindings`; this page
 * intentionally does not call the API yet.
 */
const FIXTURES: Record<string, FindingsTableRow[]> = {
  mixed: [
    {
      id: "1",
      title: "Path traversal via `read_file` tool",
      checkId: "active.path_traversal",
      severity: "critical",
      derivation: "probe",
      confidence: 0.95,
    },
    {
      id: "2",
      title: "Tool description contains an embedded instruction",
      checkId: "descriptions.injection_pattern",
      severity: "high",
      derivation: "description",
      confidence: 0.7,
    },
    {
      id: "3",
      title: "Input schema accepts an unbounded string for a path parameter",
      checkId: "static.unbounded_path_param",
      severity: "medium",
      derivation: "schema",
      confidence: 0.55,
    },
    {
      id: "4",
      title: "Server declares a capability it never exercises",
      checkId: "static.unused_capability",
      severity: "low",
      derivation: "artifact",
      confidence: null,
    },
    {
      id: "5",
      title: "Server responded to `initialize` with a supported protocol revision",
      checkId: "version_negotiation.supported_revision",
      severity: "info",
      derivation: "schema",
      confidence: 1,
    },
  ],
};

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<{ fixture?: string }>;
}) {
  const { fixture } = await searchParams;
  const rows = fixture ? FIXTURES[fixture] : undefined;

  if (!rows) {
    return (
      <main>
        <EmptyState
          title="No findings for the checks that ran"
          description="Pass ?fixture=mixed to preview the table, or run a scan from the setup screen."
        />
      </main>
    );
  }

  return (
    <main>
      <h1>Findings</h1>
      <FindingsTable rows={rows} caption="Fixture data for design-token verification" />
    </main>
  );
}
