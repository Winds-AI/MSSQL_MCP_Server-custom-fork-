#!/usr/bin/env node

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const queryArg = process.argv.slice(2).join(" ").trim();
const query =
  queryArg ||
  "SELECT DISTINCT TOP 100 classification\nFROM tpsales.dim_client\nWHERE classification IS NOT NULL;";

const transport = new StdioClientTransport({
  command: process.env.MCP_SERVER_COMMAND || "node",
  args: process.env.MCP_SERVER_ARGS
    ? JSON.parse(process.env.MCP_SERVER_ARGS)
    : ["/home/ubuntu/Desktop/Local_MCPs/MSSQL-Node-MCP/dist/index.js"],
  env: { ...process.env },
});

const client = new Client({
  name: "mcp-test-client",
  version: "1.0.0",
});

try {
  await client.connect(transport);
  const result = await client.callTool({
    name: "read_data",
    arguments: {
      query,
    },
  });
  console.log(JSON.stringify(result, null, 2));
} finally {
  await client.close();
}
