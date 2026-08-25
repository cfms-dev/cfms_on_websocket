Database migration and CI now support MySQL 9.7 LTS while retaining MySQL 8.4
LTS support. Streaming reads are scoped to their statements so they cannot
affect subsequent migration DDL.
