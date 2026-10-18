// SPDX-License-Identifier: AGPL-3.0-only
export type MonitorProvider = "tines" | "entra_agent_id";

export const PROVIDERS: Record<MonitorProvider, string> = {
  tines: "Tines",
  entra_agent_id: "Microsoft Entra",
};

/** Exactly the two providers setup offers; anything else, of any type, is not one. */
export function isMonitorProvider(value: unknown): value is MonitorProvider {
  return value === "tines" || value === "entra_agent_id";
}

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface SetupConfiguration {
  provider: MonitorProvider;
  label: string;
  team: string;
  space: string | null;
}

/** Only allow shell-neutral characters in values interpolated into the operator commands.
 * The same command is valid in PowerShell and a POSIX shell; secrets are never inputs here.
 */
export function validConfiguration(config: SetupConfiguration): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,95}$/.test(config.label)
    && (config.team === "" || /^[A-Za-z0-9._:-]{1,64}$/.test(config.team))
    && (config.space === null || UUID.test(config.space));
}

export function setupInstructions(config: SetupConfiguration, connection = "") {
  if (!validConfiguration(config) || (connection !== "" && !UUID.test(connection))) return null;
  const tines = config.provider === "tines";
  const keyFile = tines ? "local-data/monitor-tines.env" : "local-data/monitor-entra.env";
  const common = "uv run python -m execbound.monitoring.commands";
  const access = `--credential-file local-data/admin-token.txt --key-file ${keyFile}`;
  const space = config.space === null ? "" : ` --space ${config.space}`;
  const team = tines && config.team !== "" ? ` --team-id ${config.team}` : "";
  return {
    keyFile,
    environment: tines
      ? "TINES_BASE_URL=https://YOUR-TENANT.tines.com\nTINES_API_KEY=REPLACE_WITH_READ_ONLY_API_KEY"
      : "ENTRA_DIRECTORY_ID=REPLACE_WITH_DIRECTORY_UUID\nENTRA_CLIENT_ID=REPLACE_WITH_COLLECTION_APP_UUID\nENTRA_CLIENT_SECRET=REPLACE_WITH_COLLECTION_APP_SECRET",
    register: `${common} create-connection ${access} --kind ${config.provider} --label "${config.label}"${team}${space}`,
    collect: `${common} ${tines ? "collect-tines" : "collect-entra"} ${access} --connection ${connection || "CONNECTION_ID_FROM_REGISTRATION"}${tines ? " --inventory" : ""}`,
  };
}
