# Skill: SQL FILE / LOAD DATA Privilege Boundaries

## Metadata
- **Category**: discovery
- **Language**: sql c/cpp multi-engine
- **Stacks**: mysql, mariadb, postgres, oceanbase, sqlite, database
- **Signals**: load_data_infile, into_outfile, copy_from, pg_read_file, load_file

## Doctrine
File-access SQL verbs (`LOAD DATA INFILE`, `INTO OUTFILE`, `COPY ... FROM/TO`,
`pg_read_file`, `LOAD_FILE`) must require a dedicated file privilege, not merely
table INSERT/SELECT. A missing file-privilege gate turns a low-privilege account
into arbitrary file read or write.

## Discovery vectors (up to ten)
1. Map every file-access verb the engine supports and the privilege each should require.
2. Confirm the privilege-check function demands the file privilege, not just table rights.
3. Diff read vs write file verbs; one may be gated while its sibling is not.
4. Check server-side file paths for traversal and for reachability of sensitive files.
5. Look for functions and extensions that read/write files (UDFs, `COPY PROGRAM`, `pg_read_file`).
6. Inspect stacked-query and prepared-statement paths that reach the same verb.
7. Check secure-file-priv-style settings and whether the shipped default constrains paths.
8. Trace how a low-privilege role is created and whether it inherits file access implicitly.
9. Mine engine tests for file-verb permission cases as oracles.
10. Consider a chain: SQLi to a file verb where the app account holds the file privilege.

## Cross-language and stack examples
- MySQL/MariaDB: `LOAD DATA [LOCAL] INFILE`, `SELECT ... INTO OUTFILE/DUMPFILE`, `LOAD_FILE()` gated by the `FILE` privilege and `secure_file_priv`.
- PostgreSQL: `COPY ... FROM/TO`, `COPY ... PROGRAM` (superuser), `pg_read_file`/`pg_read_binary_file`, `lo_import`/`lo_export`, the `pg_read_server_files` role.
- OceanBase/TiDB and MySQL-compatible engines: the same `INFILE`/`OUTFILE` verbs, often with a weaker or stubbed privilege check.
- Microsoft SQL Server: `BULK INSERT`, `OPENROWSET(BULK ...)`, `xp_cmdshell`, `sp_OACreate` file access.
- Oracle: `UTL_FILE`, `DBMS_LOB` file ops, external tables, and directory objects.
- SQLite: `ATTACH DATABASE` to a chosen path, and application-defined file UDFs.
- Any engine: a UDF or extension that opens a path from a low-privilege session (SQLi-to-file-read/write chain).

## Lab
Create a SELECT-only (or otherwise restricted) user and attempt `LOAD DATA INFILE`
of a lab-only sentinel file, or write a sentinel via `INTO OUTFILE`/`COPY TO`.
Oracle for bypass: the file bytes appear in the table, or the sentinel file is
written. Negative control: the same statement must fail with a file-privilege
error when the gate is enforced. Require signed target-bound proof.

## Counterexamples and limits
If the file privilege is required and enforced, or paths are constrained to a
harmless directory, the lead is closed. A statement error is inconclusive, not a
finding.
