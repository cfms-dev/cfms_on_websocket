Scheduling now uses the application database clock for persisted schedule state,
retry timing, and execution leases so application-node clock skew cannot cause
premature recovery.
