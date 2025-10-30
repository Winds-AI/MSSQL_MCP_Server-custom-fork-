# Change Log (Fork)

- Increased SQL request timeout from 30s to 120s via new `REQUEST_TIMEOUT` env var, keeping millisecond conversion in one place @MssqlMcp/Node/src/index.ts#40-63.
- Added execution time output to `describe_table` responses so callers see how long metadata queries take @MssqlMcp/Node/src/tools/DescribeTableTool.ts#17-38.
- Added execution time output to `list_table` responses for quick performance insight @MssqlMcp/Node/src/tools/ListTableTool.ts#23-46.
- Added execution timing plus rich SQL error diagnostics (codes, numbers, preceding errors) to `read_data` responses @MssqlMcp/Node/src/tools/ReadDataTool.ts#203-299.