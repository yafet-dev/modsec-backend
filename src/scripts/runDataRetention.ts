/**
 * Run the data retention cleanup once.
 *
 *   npm run retention:run -- --dry-run   # count what would be deleted
 *   npm run retention:run                # delete it
 */
import "dotenv/config";
import { prisma } from "../lib/prisma";
import { runDataRetention } from "../services/dataRetentionJob";

async function main(): Promise<void> {
  const dryRun = process.argv.includes("--dry-run");
  console.log(
    dryRun
      ? "Data retention dry run (nothing is deleted)"
      : "Running data retention cleanup"
  );

  const result = await runDataRetention(new Date(), { dryRun });
  const verb = dryRun ? "would delete" : "deleted";

  for (const org of result.organizations) {
    console.log(
      `  ${org.name} (${org.organizationId}): keep logs ${org.logRetentionDays}d, raw ${org.rawRetentionDays}d, ` +
        `${verb} ${org.logsDeleted} logs and ${org.rawDeleted} raw events`
    );
  }
  console.log(
    `  Data matching no organization: keep logs ${result.unassigned.logRetentionDays}d, ` +
      `raw ${result.unassigned.rawRetentionDays}d, ${verb} ${result.unassigned.logsDeleted} logs ` +
      `and ${result.unassigned.rawDeleted} raw events`
  );
  console.log(
    `Total: ${verb} ${result.logsDeleted} logs and ${result.rawDeleted} raw events.`
  );

  if (result.errors.length > 0) {
    console.error("Errors:");
    for (const error of result.errors) console.error(`  - ${error}`);
    process.exitCode = 1;
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
