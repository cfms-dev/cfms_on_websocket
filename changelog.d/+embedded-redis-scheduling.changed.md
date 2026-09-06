Redis scheduling now runs its scheduler candidate and Dramatiq worker pool inside
each CFMS server instance. The separate `cfms-jobs` commands and jobs runtime
lock have been removed.
